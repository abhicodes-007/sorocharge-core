//! The server side of MPP's `"stellar"` `"charge"` method: issuing a
//! challenge header, and verifying + settling a received credential.
//!
//! This does not own challenge storage, an HMAC challenge-binding secret,
//! or a replay-protection set — `draft-stellar-charge-00` itself defines
//! only "the Stellar-specific `methodDetails`, `payload`, and verification
//! procedures for the `stellar` payment method," leaving challenge
//! issuance/tracking to the base `draft-httpauth-payment-01` scheme, which
//! is generic across payment methods and not this crate's concern. Callers
//! look up the `ChargeRequest` a challenge id was issued for (from
//! whatever store they already run) and hand it to
//! [`MppServer::settle_credential`] alongside the received credential.

use chrono::{DateTime, Utc};
use sorocharge_signer::{
    verify_entry, verify_transfer_effects, Address, ChargeParams, SignedEntry, Signer,
};
use stellar_xdr::{
    Hash as XdrHash, Limits, Preconditions, ReadXdr, ScAddress, SorobanCredentials,
    TransactionEnvelope,
};

use crate::error::MppError;
use crate::header::{build_www_authenticate_header, encode_base64url_jcs};
use crate::network::caip2_for_passphrase;
use crate::tx::{parse_payment_transaction, rebuild_for_settlement, sign_transaction};
use crate::types::{ChargeRequest, Credential, Payload, Receipt};

const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;

/// Server configuration. The MPP spec (unlike x402's `exact` scheme on
/// Stellar) does not mandate a specific default fee ceiling — it only says
/// servers "MUST maintain sufficient XLM balance" and "MAY reject new
/// challenges when balance is below a safe threshold." The default here
/// (50,000 stroops) is this crate's own conservative choice, made for the
/// same reason x402's facilitator has one: a fee-sponsoring server is
/// exposed to fee-exhaustion attacks, and CLAUDE.md asks for the more
/// conservative reading wherever a requirement is silent on specifics.
#[derive(Debug, Clone)]
pub struct MppServerConfig {
    pub max_transaction_fee_stroops: i64,
    pub inclusion_buffer_stroops: i64,
}

impl Default for MppServerConfig {
    fn default() -> Self {
        Self {
            max_transaction_fee_stroops: 50_000,
            inclusion_buffer_stroops: 100,
        }
    }
}

fn legacy_credential_fields(credentials: &SorobanCredentials) -> Result<(Address, u32), MppError> {
    match credentials {
        SorobanCredentials::Address(c) => Ok((c.address.clone(), c.signature_expiration_ledger)),
        _ => Err(MppError::ForbiddenCredentialType),
    }
}

fn network_id_hash(network_passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(network_passphrase.as_bytes()).into()
}

/// The MPP server: verifies and settles `"stellar"`/`"charge"` payments,
/// optionally sponsoring transaction fees from its own account.
pub struct MppServer<'a> {
    rpc: &'a stellar_rpc_client::Client,
    signer: &'a dyn Signer,
    network_passphrase: String,
    config: MppServerConfig,
}

impl<'a> MppServer<'a> {
    /// `signer` is the server's own fee-paying key, used only for the
    /// sponsored pull-mode flow.
    #[must_use]
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        signer: &'a dyn Signer,
        network_passphrase: String,
        config: MppServerConfig,
    ) -> Self {
        Self {
            rpc,
            signer,
            network_passphrase,
            config,
        }
    }

    fn server_address(&self) -> Address {
        self.signer.address()
    }

    /// Builds the `WWW-Authenticate: Payment ...` header value for a fresh
    /// `"stellar"`/`"charge"` challenge. `id` and `realm` are the caller's
    /// own — this crate has no opinion on how challenge ids are generated
    /// or how the caller's challenge store keys them.
    ///
    /// # Errors
    ///
    /// Returns [`MppError::InvalidChargeRequest`] if `request` fails to
    /// JCS-serialize (essentially never, for the types this crate defines).
    pub fn build_challenge_header(
        &self,
        id: &str,
        realm: &str,
        request: &ChargeRequest,
        expires: DateTime<Utc>,
    ) -> Result<String, MppError> {
        let request_b64 = encode_base64url_jcs(request)?;
        Ok(build_www_authenticate_header(
            id,
            realm,
            &request_b64,
            Some(&expires.to_rfc3339()),
        ))
    }

    /// Verifies and settles a received credential against `expected` — the
    /// `ChargeRequest` the caller's own challenge store recorded for
    /// `credential.challenge.id`. Returns the `Payment-Receipt` payload on
    /// success.
    ///
    /// For push-mode (`type="hash"`) credentials, replay protection (the
    /// spec's "Servers MUST maintain a set of consumed transaction hashes")
    /// is the caller's responsibility: `already_consumed` should reflect a
    /// pre-call lookup against that set, and the caller MUST mark the
    /// returned receipt's `reference` hash consumed after a successful
    /// return, atomically with respect to concurrent calls for the same
    /// hash. This function does not own that store.
    ///
    /// # Errors
    ///
    /// See [`MppError`] for the specific failure modes. A `settlement
    /// -failed`-shaped outcome (credential valid, on-chain submission
    /// failed) is reported as [`MppError::SettlementFailed`], distinct from
    /// [`MppError::VerificationFailed`].
    pub async fn settle_credential(
        &self,
        credential: &Credential,
        expected: &ChargeRequest,
        current_time: DateTime<Utc>,
        already_consumed: bool,
    ) -> Result<Receipt, MppError> {
        if credential.challenge.method != "stellar" {
            return Err(MppError::UnsupportedMethod {
                method: credential.challenge.method.clone(),
            });
        }
        if credential.challenge.intent != "charge" {
            return Err(MppError::UnsupportedIntent {
                intent: credential.challenge.intent.clone(),
            });
        }
        let echoed: ChargeRequest =
            crate::header::decode_base64url_json(&credential.challenge.request)
                .map_err(|reason| MppError::InvalidChallenge { reason })?;
        if echoed != *expected {
            return Err(MppError::InvalidChallenge {
                reason: "echoed challenge request does not match the issued challenge".to_string(),
            });
        }
        let expected_network = caip2_for_passphrase(&self.network_passphrase)?;
        if expected.method_details.network != expected_network {
            return Err(MppError::UnsupportedNetwork {
                network: expected.method_details.network.clone(),
            });
        }
        let expires_at = credential
            .challenge
            .expires
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));
        if let Some(expires_at) = expires_at {
            if current_time > expires_at {
                return Err(MppError::ChallengeExpired);
            }
        }

        let asset_contract =
            expected
                .currency
                .parse()
                .map_err(|_| MppError::InvalidChargeRequest {
                    reason: format!("invalid currency address: {}", expected.currency),
                })?;
        let amount: i128 = expected
            .amount
            .parse()
            .map_err(|_| MppError::InvalidChargeRequest {
                reason: format!("invalid amount: {}", expected.amount),
            })?;
        let recipient = expected
            .recipient
            .parse()
            .map_err(|_| MppError::InvalidChargeRequest {
                reason: format!("invalid recipient address: {}", expected.recipient),
            })?;

        match &credential.payload {
            Payload::Hash { hash } => {
                self.settle_push_mode(
                    hash,
                    expected,
                    already_consumed,
                    asset_contract,
                    amount,
                    recipient,
                )
                .await
            }
            Payload::Transaction { transaction } => {
                self.settle_pull_mode(
                    transaction,
                    expected,
                    expires_at,
                    asset_contract,
                    amount,
                    recipient,
                )
                .await
            }
        }
    }

    async fn settle_push_mode(
        &self,
        hash_hex: &str,
        expected: &ChargeRequest,
        already_consumed: bool,
        asset_contract: Address,
        amount: i128,
        recipient: Address,
    ) -> Result<Receipt, MppError> {
        if expected.method_details.fee_payer {
            return Err(MppError::PushModeForbidsFeePayer);
        }
        if already_consumed {
            return Err(MppError::HashAlreadyConsumed);
        }
        let hash_bytes: [u8; 32] =
            hex_decode_32(hash_hex).ok_or_else(|| MppError::InvalidCredential {
                reason: format!("invalid transaction hash: {hash_hex}"),
            })?;

        let response = self
            .rpc
            .get_transaction(&XdrHash(hash_bytes))
            .await
            .map_err(|e| MppError::RpcFailed {
                reason: e.to_string(),
            })?;
        if response.status != "SUCCESS" {
            return Err(MppError::VerificationFailed {
                reason: format!("transaction status is {}", response.status),
            });
        }
        let envelope = response
            .envelope
            .ok_or_else(|| MppError::VerificationFailed {
                reason: "transaction response carried no envelope".to_string(),
            })?;
        let (transfer, _tx, _auth_entry) = match parse_payment_transaction(&envelope) {
            Ok(v) => v,
            Err(MppError::ForbiddenCredentialType) => {
                // Push mode has already settled on-chain by the time we see
                // it; the credential-type restriction is a pull-mode
                // signing constraint, not something to re-litigate here.
                return Err(MppError::VerificationFailed {
                    reason: "could not parse a bare SEP-41 transfer from the transaction"
                        .to_string(),
                });
            }
            Err(e) => return Err(e),
        };
        if transfer.asset_contract != asset_contract
            || transfer.amount != amount
            || transfer.to != recipient
        {
            return Err(MppError::VerificationFailed {
                reason: "on-chain transfer does not match the charge request".to_string(),
            });
        }

        Ok(Receipt {
            method: "stellar".to_string(),
            reference: hash_hex.to_string(),
            status: "success".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            external_id: expected.external_id.clone(),
        })
    }

    async fn settle_pull_mode(
        &self,
        transaction_b64: &str,
        expected: &ChargeRequest,
        expires_at: Option<DateTime<Utc>>,
        asset_contract: Address,
        amount: i128,
        recipient: Address,
    ) -> Result<Receipt, MppError> {
        let envelope = TransactionEnvelope::from_xdr_base64(transaction_b64, Limits::none())
            .map_err(|e| MppError::XdrDecodingFailed {
                reason: e.to_string(),
            })?;
        let (transfer, tx, auth_entry) = parse_payment_transaction(&envelope)?;

        if transfer.asset_contract != asset_contract
            || transfer.amount != amount
            || transfer.to != recipient
        {
            return Err(MppError::VerificationFailed {
                reason: "transaction's transfer does not match the charge request".to_string(),
            });
        }

        let current_ledger = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| MppError::RpcFailed {
                reason: e.to_string(),
            })?
            .sequence;

        let (credential_address, signature_expiration_ledger) =
            legacy_credential_fields(&auth_entry.credentials)?;

        if let Some(expires_at) = expires_at {
            let seconds_until_expiry = (expires_at - Utc::now()).num_seconds().max(0) as u64;
            let ledger_timeout = seconds_until_expiry.div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS);
            let max_allowed_ledger =
                current_ledger.saturating_add(u32::try_from(ledger_timeout).unwrap_or(u32::MAX));
            if signature_expiration_ledger > max_allowed_ledger {
                return Err(MppError::VerificationFailed {
                    reason: "authorization entry expiration exceeds the challenge's allowance"
                        .to_string(),
                });
            }
        }

        let params = ChargeParams {
            asset_contract: asset_contract.clone(),
            amount,
            payer: credential_address,
            recipient: recipient.clone(),
            valid_until_ledger: 0,
        };
        verify_entry(
            &SignedEntry::from_xdr(auth_entry.clone()),
            &params,
            current_ledger,
            &self.network_passphrase,
        )
        .map_err(|e| MppError::VerificationFailed {
            reason: e.to_string(),
        })?;

        let sponsored = expected.method_details.fee_payer;
        if sponsored {
            let server = self.server_address();
            if transfer.from == server {
                return Err(MppError::ServerAddressConflict);
            }
            if params.payer == server {
                return Err(MppError::ServerAddressConflict);
            }
            if !matches!(&tx.source_account, stellar_xdr::MuxedAccount::Ed25519(k) if k.0 == [0u8; 32])
            {
                return Err(MppError::VerificationFailed {
                    reason: "sponsored transaction source must be the all-zeros account"
                        .to_string(),
                });
            }
        } else if let Preconditions::Time(bounds) = &tx.cond {
            if let Some(expires_at) = expires_at {
                let max_allowed = u64::try_from(expires_at.timestamp()).unwrap_or(0);
                if bounds.max_time.0 > max_allowed {
                    return Err(MppError::VerificationFailed {
                        reason: "timeBounds.maxTime exceeds the challenge expiry".to_string(),
                    });
                }
            }
        } else {
            return Err(MppError::VerificationFailed {
                reason: "unsponsored transaction must set timeBounds".to_string(),
            });
        }

        let simulation = self
            .rpc
            .simulate_transaction_envelope(&envelope, None)
            .await
            .map_err(|e| MppError::RpcFailed {
                reason: e.to_string(),
            })?;
        if let Some(error) = simulation.error {
            return Err(MppError::VerificationFailed {
                reason: format!("simulation failed: {error}"),
            });
        }
        verify_transfer_effects(
            &simulation.events,
            &params.asset_contract,
            &params.payer,
            &params.recipient,
            params.amount,
        )
        .map_err(|e| MppError::VerificationFailed {
            reason: e.to_string(),
        })?;

        let response = if sponsored {
            let ScAddress::Account(server_account_id) = self.server_address() else {
                return Err(MppError::XdrEncodingFailed {
                    reason: "server signer must be an Ed25519 account".to_string(),
                });
            };
            let account = self
                .rpc
                .get_account(&self.server_address().to_string())
                .await
                .map_err(|e| MppError::RpcFailed {
                    reason: e.to_string(),
                })?;
            let next_seq = stellar_xdr::SequenceNumber(account.seq_num.0 + 1);
            let fee = i64::try_from(simulation.min_resource_fee)
                .unwrap_or(i64::MAX)
                .saturating_add(self.config.inclusion_buffer_stroops);
            if fee > self.config.max_transaction_fee_stroops {
                return Err(MppError::VerificationFailed {
                    reason: format!(
                        "settlement fee {fee} stroops exceeds ceiling {} stroops",
                        self.config.max_transaction_fee_stroops
                    ),
                });
            }
            let soroban_data = stellar_xdr::SorobanTransactionData::from_xdr_base64(
                &simulation.transaction_data,
                Limits::none(),
            )
            .map_err(|e| MppError::XdrDecodingFailed {
                reason: e.to_string(),
            })?;
            let rebuilt = rebuild_for_settlement(
                &tx,
                server_account_id,
                u32::try_from(fee).unwrap_or(u32::MAX),
                next_seq,
                soroban_data,
            );
            let network_id = network_id_hash(&self.network_passphrase);
            let signed_envelope = sign_transaction(rebuilt, self.signer, network_id)?;
            self.rpc
                .send_transaction_polling(&signed_envelope)
                .await
                .map_err(|e| MppError::SettlementFailed {
                    reason: e.to_string(),
                })?
        } else {
            self.rpc
                .send_transaction_polling(&envelope)
                .await
                .map_err(|e| MppError::SettlementFailed {
                    reason: e.to_string(),
                })?
        };

        if response.status != "SUCCESS" {
            return Err(MppError::SettlementFailed {
                reason: response.status,
            });
        }

        Ok(Receipt {
            method: "stellar".to_string(),
            reference: response.tx_hash.unwrap_or_default(),
            status: "success".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            external_id: expected.external_id.clone(),
        })
    }
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(out)
}
