//! The facilitator side of x402: `/verify`, `/settle`, and `/supported`.
//!
//! These are plain async functions operating on already-deserialized
//! request/response types, not an HTTP server — wiring them to the actual
//! `/verify`, `/settle`, `/supported` HTTP paths is left to whatever web
//! framework the embedding application already uses. This mirrors
//! `sorocharge-signer`'s own non-goal ("not a general-purpose Soroban
//! contract client" / "not a CLI"): this crate translates wire formats, it
//! does not also ship a server.

use std::collections::BTreeMap;

use sorocharge_signer::{
    verify_entry, verify_transfer_effects, Address, ChargeParams, SignedEntry, Signer,
};
use stellar_xdr::{
    AccountId, Limits, PublicKey, ReadXdr, ScAddress, SequenceNumber, SorobanCredentials,
    TransactionEnvelope, TransactionExt, Uint256,
};

use crate::error::X402Error;
use crate::network::caip2_for_passphrase;
use crate::tx::{parse_payment_transaction, rebuild_for_settlement, sign_transaction};
use crate::types::{
    SettleRequest, SettlementResponse, SupportedKind, SupportedResponse, VerifyRequest,
    VerifyResponse,
};

/// Fallback average Stellar ledger close time, used to convert
/// `maxTimeoutSeconds` into a ledger count when a live network estimate
/// isn't available. Matches the spec's own fallback.
const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;
/// The default safety ceiling on a settlement's simulation-derived fee, per
/// the spec's suggested default.
const DEFAULT_MAX_TRANSACTION_FEE_STROOPS: i64 = 50_000;
/// The spec's required minimum inclusion buffer added to the simulated
/// resource fee.
pub const MIN_INCLUSION_BUFFER_STROOPS: i64 = 100;

/// Facilitator configuration: the fee-safety ceiling and inclusion buffer
/// the spec makes an operator-configurable circuit breaker rather than a
/// protocol constant.
#[derive(Debug, Clone)]
pub struct FacilitatorConfig {
    pub max_transaction_fee_stroops: i64,
    pub inclusion_buffer_stroops: i64,
}

impl Default for FacilitatorConfig {
    fn default() -> Self {
        Self {
            max_transaction_fee_stroops: DEFAULT_MAX_TRANSACTION_FEE_STROOPS,
            inclusion_buffer_stroops: MIN_INCLUSION_BUFFER_STROOPS,
        }
    }
}

fn credential_address(credentials: &SorobanCredentials) -> Option<Address> {
    match credentials {
        SorobanCredentials::Address(c) => Some(c.address.clone()),
        SorobanCredentials::AddressV2(c) => Some(c.address.clone()),
        SorobanCredentials::SourceAccount | SorobanCredentials::AddressWithDelegates(_) => None,
    }
}

/// The x402 facilitator: verifies and settles `exact`-scheme payments on
/// Stellar, sponsoring transaction fees from its own account.
pub struct Facilitator<'a> {
    rpc: &'a stellar_rpc_client::Client,
    signer: &'a dyn Signer,
    network_passphrase: String,
    config: FacilitatorConfig,
}

impl<'a> Facilitator<'a> {
    /// `signer` is the facilitator's own fee-paying key: the account that
    /// becomes every settled transaction's source account.
    #[must_use]
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        signer: &'a dyn Signer,
        network_passphrase: String,
        config: FacilitatorConfig,
    ) -> Self {
        Self {
            rpc,
            signer,
            network_passphrase,
            config,
        }
    }

    fn facilitator_address(&self) -> Address {
        self.signer.address()
    }

    /// Decodes and structurally validates a payment, without touching
    /// chain state beyond a read-only simulation. Returns the parsed
    /// transaction pieces alongside the `ChargeParams` a caller can hand to
    /// `sorocharge_signer::verify_entry` — which this function has already
    /// called once, so a passing return here already carries a verified
    /// signature.
    async fn validate(
        &self,
        request: &VerifyRequest,
    ) -> Result<
        (
            stellar_xdr::Transaction,
            stellar_xdr::SorobanAuthorizationEntry,
            ChargeParams,
        ),
        X402Error,
    > {
        if request.x402_version != 2 {
            return Err(X402Error::InvalidPaymentPayload {
                reason: format!("unsupported x402Version {}", request.x402_version),
            });
        }
        if request.payment_payload.accepted.scheme != "exact"
            || request.payment_requirements.scheme != "exact"
        {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "expected scheme \"exact\"".to_string(),
            });
        }
        if request.payment_payload.accepted.network != request.payment_requirements.network {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "payload.accepted.network does not match paymentRequirements.network"
                    .to_string(),
            });
        }
        let expected_network = caip2_for_passphrase(&self.network_passphrase)?;
        if request.payment_requirements.network != expected_network {
            return Err(X402Error::UnsupportedNetwork {
                network: request.payment_requirements.network.clone(),
            });
        }

        let envelope = TransactionEnvelope::from_xdr_base64(
            &request.payment_payload.payload.transaction,
            Limits::none(),
        )
        .map_err(|e| X402Error::XdrDecodingFailed {
            reason: e.to_string(),
        })?;
        let (transfer, tx, auth_entry) = parse_payment_transaction(&envelope)?;

        let facilitator = self.facilitator_address();
        if let Some(op) = tx.operations.first() {
            if let Some(op_source) = &op.source_account {
                if tx_source_matches(op_source, &facilitator) {
                    return Err(X402Error::FacilitatorAddressConflict);
                }
            }
        }
        if tx_source_matches(&tx.source_account, &facilitator) {
            return Err(X402Error::FacilitatorAddressConflict);
        }
        if transfer.from == facilitator {
            return Err(X402Error::FacilitatorAddressConflict);
        }
        if credential_address(&auth_entry.credentials).as_ref() == Some(&facilitator) {
            return Err(X402Error::FacilitatorAddressConflict);
        }

        let requirements = &request.payment_requirements;
        let asset_contract =
            requirements
                .asset
                .parse()
                .map_err(|_| X402Error::InvalidPaymentPayload {
                    reason: format!("invalid asset address: {}", requirements.asset),
                })?;
        let amount = requirements
            .amount
            .parse()
            .map_err(|_| X402Error::InvalidPaymentPayload {
                reason: format!("invalid amount: {}", requirements.amount),
            })?;
        let recipient =
            requirements
                .pay_to
                .parse()
                .map_err(|_| X402Error::InvalidPaymentPayload {
                    reason: format!("invalid payTo address: {}", requirements.pay_to),
                })?;

        if transfer.asset_contract != asset_contract
            || transfer.amount != amount
            || transfer.to != recipient
        {
            return Err(X402Error::InvalidPaymentPayload {
                reason: "transaction's transfer does not match paymentRequirements".to_string(),
            });
        }

        let current_ledger = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?
            .sequence;

        // The spec: "the auth entry expiration ledger MUST NOT exceed
        // currentLedger + ceil(maxTimeoutSeconds / estimatedLedgerSeconds)."
        // This is also what verify_entry's ExpirationExceedsAllowance check
        // enforces against expected.valid_until_ledger, so it has to be the
        // real cap, not a placeholder.
        let max_timeout_ledgers = requirements
            .max_timeout_seconds
            .div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS);
        let valid_until_ledger =
            current_ledger.saturating_add(u32::try_from(max_timeout_ledgers).unwrap_or(u32::MAX));

        let params = ChargeParams {
            asset_contract,
            amount,
            payer: transfer.from.clone(),
            recipient,
            valid_until_ledger,
        };
        verify_entry(
            &SignedEntry::from_xdr(auth_entry.clone()),
            &params,
            current_ledger,
            &self.network_passphrase,
        )
        .map_err(|e| X402Error::InvalidPaymentPayload {
            reason: e.to_string(),
        })?;

        let simulation = self
            .rpc
            .simulate_transaction_envelope(&envelope, None)
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        if let Some(error) = simulation.error {
            return Err(X402Error::InvalidPaymentPayload {
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
        .map_err(|e| X402Error::InvalidPaymentPayload {
            reason: e.to_string(),
        })?;

        Ok((tx, auth_entry, params))
    }

    /// `POST /verify`: read-only validation, per spec §7.1.
    pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, X402Error> {
        match self.validate(request).await {
            Ok((_, _, params)) => Ok(VerifyResponse {
                is_valid: true,
                invalid_reason: None,
                payer: Some(params.payer.to_string()),
            }),
            Err(e) => Ok(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(e.to_string()),
                payer: None,
            }),
        }
    }

    /// `POST /settle`: performs full verification independently (per spec:
    /// "`/settle` MUST NOT assume prior verification"), then rebuilds the
    /// transaction with the facilitator as source account, re-simulates to
    /// derive a fresh fee and resource footprint, signs, submits, and polls
    /// for confirmation.
    pub async fn settle(&self, request: &SettleRequest) -> Result<SettlementResponse, X402Error> {
        let network = request.payment_requirements.network.clone();
        let (tx, _auth_entry, params) = match self.validate(request).await {
            Ok(v) => v,
            Err(e) => {
                return Ok(SettlementResponse {
                    success: false,
                    error_reason: Some(e.to_string()),
                    payer: None,
                    transaction: String::new(),
                    network,
                    amount: None,
                });
            }
        };

        let ScAddress::Account(facilitator_account_id) = self.facilitator_address() else {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some("facilitator signer must be an Ed25519 account".to_string()),
                payer: None,
                transaction: String::new(),
                network,
                amount: None,
            });
        };

        let account = self
            .rpc
            .get_account(&self.facilitator_address().to_string())
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        let next_seq_num = SequenceNumber(account.seq_num.0 + 1);

        // Refresh Soroban resource data and fee from a settle-time
        // simulation of the tx as the facilitator will actually submit it
        // (same operations/auth, facilitator source/sequence).
        let unsigned_for_sim = rebuild_for_settlement(
            &tx,
            facilitator_account_id.clone(),
            0,
            next_seq_num.clone(),
            TransactionExt::V0,
        );
        let sim_envelope = TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
            tx: unsigned_for_sim,
            signatures: Default::default(),
        });
        let simulation = self
            .rpc
            .simulate_transaction_envelope(&sim_envelope, None)
            .await
            .map_err(|e| X402Error::RpcFailed {
                reason: e.to_string(),
            })?;
        if let Some(error) = simulation.error {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some(format!("settlement simulation failed: {error}")),
                payer: Some(params.payer.to_string()),
                transaction: String::new(),
                network,
                amount: None,
            });
        }
        if let Err(e) = verify_transfer_effects(
            &simulation.events,
            &params.asset_contract,
            &params.payer,
            &params.recipient,
            params.amount,
        ) {
            return Ok(SettlementResponse {
                success: false,
                error_reason: Some(format!("settlement effects rejected: {e}")),
                payer: Some(params.payer.to_string()),
                transaction: String::new(),
                network,
                amount: None,
            });
        }

        let fee = i64::try_from(simulation.min_resource_fee)
            .unwrap_or(i64::MAX)
            .saturating_add(self.config.inclusion_buffer_stroops);
        if fee > self.config.max_transaction_fee_stroops {
            return Err(X402Error::FeeExceedsCeiling {
                fee_stroops: fee,
                ceiling_stroops: self.config.max_transaction_fee_stroops,
            });
        }
        let soroban_data = stellar_xdr::SorobanTransactionData::from_xdr_base64(
            &simulation.transaction_data,
            Limits::none(),
        )
        .map_err(|e| X402Error::XdrDecodingFailed {
            reason: e.to_string(),
        })?;

        let final_tx = rebuild_for_settlement(
            &tx,
            facilitator_account_id,
            u32::try_from(fee).unwrap_or(u32::MAX),
            next_seq_num,
            TransactionExt::V1(soroban_data),
        );

        let network_id = network_id_hash(&self.network_passphrase);
        let signed_envelope = sign_transaction(final_tx, self.signer, network_id)?;
        let TransactionEnvelope::Tx(signed_v1) = &signed_envelope else {
            unreachable!("sign_transaction always returns a v1 envelope")
        };

        let response = self
            .rpc
            .send_transaction_polling(&TransactionEnvelope::Tx(signed_v1.clone()))
            .await
            .map_err(|e| X402Error::SettlementFailed {
                reason: e.to_string(),
            })?;

        let transaction_hash = response.tx_hash.unwrap_or_default();
        Ok(SettlementResponse {
            success: response.status == "SUCCESS",
            error_reason: if response.status == "SUCCESS" {
                None
            } else {
                Some(response.status)
            },
            payer: Some(params.payer.to_string()),
            transaction: transaction_hash,
            network,
            amount: Some(params.amount.to_string()),
        })
    }

    /// `GET /supported`: advertises `exact` on whichever Stellar network
    /// this facilitator instance was configured for, and its own signer
    /// address.
    #[must_use]
    pub fn supported(&self) -> SupportedResponse {
        let network = caip2_for_passphrase(&self.network_passphrase)
            .unwrap_or("stellar:testnet")
            .to_string();
        let mut signers = BTreeMap::new();
        signers.insert(
            "stellar:*".to_string(),
            vec![self.facilitator_address().to_string()],
        );
        SupportedResponse {
            kinds: vec![SupportedKind {
                x402_version: 2,
                scheme: "exact".to_string(),
                network,
            }],
            extensions: vec![],
            signers,
        }
    }
}

fn tx_source_matches(source: &stellar_xdr::MuxedAccount, address: &Address) -> bool {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(address_bytes)))) =
        address
    else {
        return false;
    };
    match source {
        stellar_xdr::MuxedAccount::Ed25519(Uint256(bytes)) => bytes == address_bytes,
        stellar_xdr::MuxedAccount::MuxedEd25519(m) => &m.ed25519.0 == address_bytes,
    }
}

fn network_id_hash(network_passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(network_passphrase.as_bytes()).into()
}
