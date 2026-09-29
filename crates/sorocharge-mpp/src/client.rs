//! The payer side of MPP's `"stellar"` `"charge"` method: `GET` a resource,
//! receive a `Payment` challenge, build and sign a charge (pull mode,
//! sponsored or unsponsored), and retry with the credential attached.

use chrono::{DateTime, Utc};
use sorocharge_signer::{build_charge_entry, sign_entry, ChargeParams, CredentialKind, Signer};
use stellar_xdr::{
    AccountId, Limits, PublicKey, ReadXdr, ScAddress, SorobanTransactionData, WriteXdr,
};

use crate::error::MppError;
use crate::header::{decode_base64url_json, encode_base64url_jcs};
use crate::network::caip2_for_passphrase;
use crate::tx::{build_sponsored_envelope, build_unsponsored_transaction, sign_transaction};
use crate::types::{Challenge, ChargeRequest, Credential, Payload};

const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;
const DEFAULT_CHALLENGE_EXPIRY_SECONDS: i64 = 300;
const SETTLEMENT_FEE_BUFFER_STROOPS: i64 = 100;

fn network_id_hash(network_passphrase: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(network_passphrase.as_bytes()).into()
}

fn parse_expires(expires: Option<&str>) -> DateTime<Utc> {
    expires
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(DEFAULT_CHALLENGE_EXPIRY_SECONDS))
}

/// The MPP payer client. Owns a Stellar RPC client because, unlike x402,
/// the unsponsored flow needs the payer's own account sequence number and a
/// fee/resource-data simulation before it can build a fully-signed
/// transaction — pushing that onto the caller would just move the same RPC
/// calls one layer up.
pub struct MppClient<'a> {
    http: reqwest::Client,
    rpc: &'a stellar_rpc_client::Client,
}

impl<'a> MppClient<'a> {
    /// # Errors
    ///
    /// Returns [`MppError::HttpRequestFailed`] if the underlying HTTP
    /// client fails to construct.
    pub fn new(
        rpc: &'a stellar_rpc_client::Client,
        request_timeout: std::time::Duration,
    ) -> Result<Self, MppError> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| MppError::HttpRequestFailed {
                reason: e.to_string(),
            })?;
        Ok(Self { http, rpc })
    }

    /// Performs the full MPP client flow against `url`: `GET`, decode the
    /// `WWW-Authenticate: Payment` challenge, build and sign a charge per
    /// the challenge's `feePayer` setting, and retry with the credential
    /// attached in the header the challenge selected (`Authorization` by
    /// default, or `Payment-Authorization` when the challenge requested
    /// it).
    ///
    /// # Errors
    ///
    /// See [`MppError`] for the specific failure modes.
    pub async fn get_with_payment(
        &self,
        url: &str,
        signer: &dyn Signer,
        network_passphrase: &str,
    ) -> Result<reqwest::Response, MppError> {
        let first = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| MppError::HttpRequestFailed {
                reason: e.to_string(),
            })?;
        if first.status() == reqwest::StatusCode::OK {
            return Ok(first);
        }
        if first.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Err(MppError::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        }

        let www_authenticate = first
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .ok_or(MppError::MissingChallenge)?
            .to_str()
            .map_err(|e| MppError::InvalidChallenge {
                reason: e.to_string(),
            })?;
        let params = crate::header::parse_payment_auth_params(www_authenticate)?;

        let id = params
            .get("id")
            .filter(|v| !v.is_empty())
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"id\"".to_string(),
            })?
            .clone();
        let realm = params
            .get("realm")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"realm\"".to_string(),
            })?
            .clone();
        let method = params
            .get("method")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"method\"".to_string(),
            })?
            .clone();
        if method != "stellar" {
            return Err(MppError::UnsupportedMethod { method });
        }
        let intent = params
            .get("intent")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"intent\"".to_string(),
            })?
            .clone();
        if intent != "charge" {
            return Err(MppError::UnsupportedIntent { intent });
        }
        let request_b64 = params
            .get("request")
            .ok_or_else(|| MppError::InvalidChallenge {
                reason: "missing \"request\"".to_string(),
            })?
            .clone();
        let expires = params.get("expires").cloned();
        let header_field = params.get("header").cloned();

        let charge_request: ChargeRequest = decode_base64url_json(&request_b64)
            .map_err(|reason| MppError::InvalidChargeRequest { reason })?;

        let network = caip2_for_passphrase(network_passphrase)?;
        if charge_request.method_details.network != network {
            return Err(MppError::UnsupportedNetwork {
                network: charge_request.method_details.network,
            });
        }

        let expires_at = parse_expires(expires.as_deref());
        if expires_at <= Utc::now() {
            return Err(MppError::ChallengeExpired);
        }

        let current_ledger = self
            .rpc
            .get_latest_ledger()
            .await
            .map_err(|e| MppError::RpcFailed {
                reason: e.to_string(),
            })?
            .sequence;
        let seconds_until_expiry = (expires_at - Utc::now()).num_seconds().max(0) as u64;
        let ledger_timeout = seconds_until_expiry.div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS);
        let valid_until_ledger =
            current_ledger.saturating_add(u32::try_from(ledger_timeout).unwrap_or(u32::MAX));

        let asset_contract =
            charge_request
                .currency
                .parse()
                .map_err(|_| MppError::InvalidChargeRequest {
                    reason: format!("invalid currency address: {}", charge_request.currency),
                })?;
        let amount = charge_request
            .amount
            .parse()
            .map_err(|_| MppError::InvalidChargeRequest {
                reason: format!("invalid amount: {}", charge_request.amount),
            })?;
        let recipient =
            charge_request
                .recipient
                .parse()
                .map_err(|_| MppError::InvalidChargeRequest {
                    reason: format!("invalid recipient address: {}", charge_request.recipient),
                })?;
        let params_ = ChargeParams {
            asset_contract,
            amount,
            payer: signer.address(),
            recipient,
            valid_until_ledger,
        };

        let unsigned = build_charge_entry(&params_, CredentialKind::Legacy)?;
        let signed = sign_entry(unsigned, signer, network_passphrase)?;

        let payload = if charge_request.method_details.fee_payer {
            let envelope = build_sponsored_envelope(&params_, &signed)?;
            let transaction = envelope.to_xdr_base64(Limits::none()).map_err(|e| {
                MppError::XdrEncodingFailed {
                    reason: e.to_string(),
                }
            })?;
            Payload::Transaction { transaction }
        } else {
            let ScAddress::Account(payer_account_id) = params_.payer.clone() else {
                return Err(MppError::XdrEncodingFailed {
                    reason: "payer must be an Ed25519 account for unsponsored payments".to_string(),
                });
            };
            let account = self
                .rpc
                .get_account(&params_.payer.to_string())
                .await
                .map_err(|e| MppError::RpcFailed {
                    reason: e.to_string(),
                })?;
            let next_seq = stellar_xdr::SequenceNumber(account.seq_num.0 + 1);
            let max_time_unix = u64::try_from(expires_at.timestamp()).unwrap_or(0);

            let draft_tx = build_unsponsored_transaction(
                &params_,
                &signed,
                payer_account_id.clone(),
                next_seq.clone(),
                0,
                SorobanTransactionData::default(),
                max_time_unix,
            )?;
            let draft_envelope =
                stellar_xdr::TransactionEnvelope::Tx(stellar_xdr::TransactionV1Envelope {
                    tx: draft_tx,
                    signatures: Default::default(),
                });
            let simulation = self
                .rpc
                .simulate_transaction_envelope(&draft_envelope, None)
                .await
                .map_err(|e| MppError::RpcFailed {
                    reason: e.to_string(),
                })?;
            if let Some(error) = simulation.error {
                return Err(MppError::VerificationFailed {
                    reason: format!("simulation failed: {error}"),
                });
            }
            let fee = i64::try_from(simulation.min_resource_fee)
                .unwrap_or(i64::MAX)
                .saturating_add(SETTLEMENT_FEE_BUFFER_STROOPS);
            let soroban_data = SorobanTransactionData::from_xdr_base64(
                &simulation.transaction_data,
                Limits::none(),
            )
            .map_err(|e| MppError::XdrDecodingFailed {
                reason: e.to_string(),
            })?;

            let final_tx = build_unsponsored_transaction(
                &params_,
                &signed,
                payer_account_id,
                next_seq,
                u32::try_from(fee).unwrap_or(u32::MAX),
                soroban_data,
                max_time_unix,
            )?;
            let network_id = network_id_hash(network_passphrase);
            let signed_envelope = sign_transaction(final_tx, signer, network_id)?;
            let transaction = signed_envelope.to_xdr_base64(Limits::none()).map_err(|e| {
                MppError::XdrEncodingFailed {
                    reason: e.to_string(),
                }
            })?;
            Payload::Transaction { transaction }
        };

        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(_))) = params_.payer
        else {
            return Err(MppError::XdrEncodingFailed {
                reason: "payer must be an Ed25519 account".to_string(),
            });
        };
        let source = format!("did:pkh:{network}:{}", params_.payer);

        let credential = Credential {
            challenge: Challenge {
                id,
                realm,
                method,
                intent,
                request: request_b64,
                description: params.get("description").cloned(),
                opaque: params.get("opaque").cloned(),
                digest: params.get("digest").cloned(),
                expires,
                header: header_field.clone(),
            },
            payload,
            source: Some(source),
        };
        let credential_value = encode_base64url_jcs(&credential)?;

        let header_name = match header_field.as_deref() {
            Some("Payment-Authorization") => "Payment-Authorization",
            _ => "Authorization",
        };
        let second = self
            .http
            .get(url)
            .header(header_name, format!("Payment {credential_value}"))
            .send()
            .await
            .map_err(|e| MppError::HttpRequestFailed {
                reason: e.to_string(),
            })?;

        if second.status() != reqwest::StatusCode::OK {
            return Err(MppError::UnexpectedStatus {
                status: second.status().as_u16(),
            });
        }
        Ok(second)
    }
}
