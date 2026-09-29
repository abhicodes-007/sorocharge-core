//! The payer side of x402: `GET` a resource, receive `402` with payment
//! terms, build and sign a charge entry via `sorocharge-signer`, and retry
//! with the signed credential attached.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use stellar_xdr::{Limits, WriteXdr};

use sorocharge_signer::{build_charge_entry, sign_entry, ChargeParams, CredentialKind, Signer};

use crate::error::X402Error;
use crate::network::caip2_for_passphrase;
use crate::tx::build_payment_transaction_envelope;
use crate::types::{PaymentPayload, PaymentRequired, PaymentRequirements, StellarPayload};

pub const PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";
pub const PAYMENT_SIGNATURE_HEADER: &str = "PAYMENT-SIGNATURE";

/// The default estimate of a Stellar ledger's close time, used to convert
/// `maxTimeoutSeconds` into a ledger count when the live network estimate
/// isn't available. Matches the spec's own fallback.
const DEFAULT_ESTIMATED_LEDGER_SECONDS: u64 = 5;

fn decode_header_json<T: serde::de::DeserializeOwned>(header_value: &str) -> Result<T, String> {
    let bytes = BASE64
        .decode(header_value.trim())
        .map_err(|e| format!("base64 decode failed: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON decode failed: {e}"))
}

fn encode_header_json<T: serde::Serialize>(value: &T) -> Result<String, X402Error> {
    let bytes = serde_json::to_vec(value).map_err(|e| X402Error::InvalidPaymentPayload {
        reason: e.to_string(),
    })?;
    Ok(BASE64.encode(bytes))
}

/// The x402 payer client: performs the `GET` → `402` → build/sign → retry
/// flow against a resource server speaking x402 protocol v2's `exact`
/// scheme on Stellar.
pub struct X402Client {
    http: reqwest::Client,
}

impl X402Client {
    /// Builds a client whose every HTTP request is bounded by
    /// `request_timeout` — no unbounded waits on a resource server.
    ///
    /// # Errors
    ///
    /// Returns [`X402Error::HttpRequestFailed`] if the underlying HTTP
    /// client fails to construct (e.g. a broken TLS backend).
    pub fn new(request_timeout: std::time::Duration) -> Result<Self, X402Error> {
        let http = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| X402Error::HttpRequestFailed {
                reason: e.to_string(),
            })?;
        Ok(Self { http })
    }

    /// Selects the `accepts[]` entry naming the `exact` scheme on the
    /// Stellar network identified by `network_passphrase`, and builds the
    /// `ChargeParams` it describes for `payer`.
    fn select_requirements_and_params(
        payment_required: &PaymentRequired,
        network_passphrase: &str,
        payer: sorocharge_signer::Address,
    ) -> Result<(PaymentRequirements, ChargeParams), X402Error> {
        let network = caip2_for_passphrase(network_passphrase)?;
        let requirements = payment_required
            .accepts
            .iter()
            .find(|r| r.scheme == "exact" && r.network == network)
            .cloned()
            .ok_or(X402Error::NoAcceptablePaymentRequirements)?;

        let asset_contract =
            requirements
                .asset
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid asset address: {}", requirements.asset),
                })?;
        let amount =
            requirements
                .amount
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid amount: {}", requirements.amount),
                })?;
        let recipient =
            requirements
                .pay_to
                .parse()
                .map_err(|_| X402Error::InvalidPaymentRequired {
                    reason: format!("invalid payTo address: {}", requirements.pay_to),
                })?;

        Ok((
            requirements,
            ChargeParams {
                asset_contract,
                amount,
                payer,
                recipient,
                valid_until_ledger: 0, // filled in by the caller once currentLedger is known
            },
        ))
    }

    /// Performs the full x402 client flow against `url`:
    ///
    /// 1. `GET url`. A `200` is returned as-is (already paid, or free).
    /// 2. On `402`, decode `PAYMENT-REQUIRED`, pick the `exact`-on-Stellar
    ///    entry matching `network_passphrase`, and build+sign a
    ///    `Legacy`-credential charge entry via `sorocharge-signer` for
    ///    `signer`. `Legacy` is chosen over `AddressV2` for the broadest
    ///    facilitator compatibility, even though the spec permits both:
    ///    "recording-mode simulation still returns the legacy arm as of
    ///    Protocol 28."
    /// 3. Wrap the signed entry in a `TransactionEnvelope` and retry with
    ///    `PAYMENT-SIGNATURE` attached.
    ///
    /// `current_ledger` is the caller-supplied result of a `getLatestLedger`
    /// RPC call, used to compute the authorization entry's expiration per
    /// the spec's `currentLedger + ceil(maxTimeoutSeconds / 5)` formula.
    /// Fetching it is left to the caller rather than done here so this
    /// method doesn't have to own an RPC client for a single read.
    ///
    /// # Errors
    ///
    /// See [`X402Error`] for the specific failure modes.
    pub async fn get_with_payment(
        &self,
        url: &str,
        signer: &dyn Signer,
        network_passphrase: &str,
        current_ledger: u32,
    ) -> Result<reqwest::Response, X402Error> {
        let first = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| X402Error::HttpRequestFailed {
                reason: e.to_string(),
            })?;

        if first.status() == reqwest::StatusCode::OK {
            return Ok(first);
        }
        if first.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Err(X402Error::UnexpectedStatus {
                status: first.status().as_u16(),
            });
        }

        let header_value = first
            .headers()
            .get(PAYMENT_REQUIRED_HEADER)
            .ok_or(X402Error::MissingPaymentRequiredHeader)?
            .to_str()
            .map_err(|e| X402Error::InvalidPaymentRequired {
                reason: e.to_string(),
            })?;
        let payment_required = decode_header_json::<PaymentRequired>(header_value)
            .map_err(|reason| X402Error::InvalidPaymentRequired { reason })?;

        let (requirements, mut params) = Self::select_requirements_and_params(
            &payment_required,
            network_passphrase,
            signer.address(),
        )?;

        let ledger_timeout = requirements
            .max_timeout_seconds
            .div_ceil(DEFAULT_ESTIMATED_LEDGER_SECONDS);
        params.valid_until_ledger =
            current_ledger.saturating_add(u32::try_from(ledger_timeout).unwrap_or(u32::MAX));

        let unsigned = build_charge_entry(&params, CredentialKind::Legacy)?;
        let signed = sign_entry(unsigned, signer, network_passphrase)?;
        let envelope = build_payment_transaction_envelope(&params, &signed)?;
        let transaction_xdr =
            envelope
                .to_xdr_base64(Limits::none())
                .map_err(|e| X402Error::XdrEncodingFailed {
                    reason: e.to_string(),
                })?;

        let payload = PaymentPayload {
            x402_version: 2,
            resource: Some(payment_required.resource.clone()),
            accepted: requirements,
            payload: StellarPayload {
                transaction: transaction_xdr,
            },
            extensions: serde_json::Map::new(),
        };
        let header_value = encode_header_json(&payload)?;

        let second = self
            .http
            .get(url)
            .header(PAYMENT_SIGNATURE_HEADER, header_value)
            .send()
            .await
            .map_err(|e| X402Error::HttpRequestFailed {
                reason: e.to_string(),
            })?;

        if second.status() != reqwest::StatusCode::OK {
            return Err(X402Error::UnexpectedStatus {
                status: second.status().as_u16(),
            });
        }
        Ok(second)
    }
}
