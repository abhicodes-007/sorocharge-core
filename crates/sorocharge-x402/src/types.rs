//! JSON wire types for the x402 protocol v2, scoped to the Stellar `exact`
//! scheme (`specs/schemes/exact/scheme_exact_stellar.md` in
//! `x402-foundation/x402`). Field names and shapes are copied verbatim from
//! that spec, not inferred — this crate does not invent wire formats for a
//! protocol it doesn't own.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The protected resource a `PaymentRequired`/`PaymentPayload` concerns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// The `extra` object the `exact` scheme on Stellar requires inside each
/// `PaymentRequirements` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StellarExtra {
    /// Whether the facilitator sponsors transaction fees. Per the spec this
    /// is "currently always true"; a non-sponsored flow does not exist yet.
    pub are_fees_sponsored: bool,
}

/// One acceptable way to pay, as carried in `PaymentRequired.accepts[]` and
/// echoed back in `PaymentPayload.accepted`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Always `"exact"` for what this crate implements.
    pub scheme: String,
    /// CAIP-2 identifier: `"stellar:pubnet"` or `"stellar:testnet"`.
    pub network: String,
    /// Required amount, in the asset's atomic (base) units, as a decimal
    /// string.
    pub amount: String,
    /// The SEP-41 SAC contract address (`C...`).
    pub asset: String,
    /// The recipient account address (`G...`).
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub extra: StellarExtra,
}

/// The `402 Payment Required` response body, carried base64-encoded in the
/// `PAYMENT-REQUIRED` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    /// Protocol version identifier; always `2` for what this crate speaks.
    pub x402_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The Stellar `exact` scheme's `payload` field: a base64-encoded XDR
/// `TransactionEnvelope` with a single `invokeHostFunction` operation and
/// signed authorization entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StellarPayload {
    pub transaction: String,
}

/// The credential a client sends back, carried base64-encoded in the
/// `PAYMENT-SIGNATURE` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: StellarPayload,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// The result of on-chain settlement, carried base64-encoded in the
/// `PAYMENT-RESPONSE` header, and returned as the JSON body of a
/// facilitator's `/settle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// The transaction hash, or an empty string if none was broadcast.
    pub transaction: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// The JSON body a facilitator's `/verify` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// The JSON body a resource server sends to a facilitator's `/verify` or
/// `/settle` (identical shape for both, per spec §7.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub x402_version: u32,
    pub payment_payload: PaymentPayload,
    pub payment_requirements: PaymentRequirements,
}

/// `/settle` takes the identical request shape as `/verify`.
pub type SettleRequest = VerifyRequest;

/// One entry in a facilitator's `/supported` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
}

/// The JSON body a facilitator's `/supported` returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    pub extensions: Vec<String>,
    /// CAIP-2 pattern (e.g. `"stellar:*"`) to the facilitator's signer
    /// addresses.
    pub signers: BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `specs/schemes/exact/scheme_exact_stellar.md`'s
    /// `PaymentRequirements` example in `x402-foundation/x402`.
    const PAYMENT_REQUIREMENTS_JSON: &str = r#"
    {
      "scheme": "exact",
      "network": "stellar:testnet",
      "amount": "10000000",
      "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
      "payTo": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO",
      "maxTimeoutSeconds": 60,
      "extra": {
        "areFeesSponsored": true
      }
    }
    "#;

    /// Verbatim from the same spec's "Full `PaymentPayload` object" example.
    const PAYMENT_PAYLOAD_JSON: &str = r#"
    {
      "x402Version": 2,
      "resource": {
        "url": "https://example.com/weather",
        "description": "Access to protected content",
        "mimeType": "application/json"
      },
      "accepted": {
        "scheme": "exact",
        "network": "stellar:testnet",
        "amount": "10000000",
        "asset": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
        "payTo": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO",
        "maxTimeoutSeconds": 60,
        "extra": {
          "areFeesSponsored": true
        }
      },
      "payload": {
        "transaction": "AAAAAgAAAABriIN4poutFUmHfB6FbFJu8GgXoPPTGQWREqFpPfvO1AAAAAAAAAAAAAAAAAAAAA..."
      }
    }
    "#;

    /// Verbatim from the same spec's `SettlementResponse` example.
    const SETTLEMENT_RESPONSE_JSON: &str = r#"
    {
      "success": true,
      "transaction": "a1b2c3d4e5f6...",
      "network": "stellar:testnet",
      "payer": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO"
    }
    "#;

    #[test]
    fn payment_requirements_matches_spec_example_field_for_field() {
        let parsed: PaymentRequirements = serde_json::from_str(PAYMENT_REQUIREMENTS_JSON).unwrap();
        assert_eq!(parsed.scheme, "exact");
        assert_eq!(parsed.network, "stellar:testnet");
        assert_eq!(parsed.amount, "10000000");
        assert_eq!(
            parsed.asset,
            "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA"
        );
        assert_eq!(
            parsed.pay_to,
            "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO"
        );
        assert_eq!(parsed.max_timeout_seconds, 60);
        assert!(parsed.extra.are_fees_sponsored);

        // Round-trip: re-serializing must reproduce the spec's exact field names.
        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in [
            "scheme",
            "network",
            "amount",
            "asset",
            "payTo",
            "maxTimeoutSeconds",
            "extra",
        ] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
        assert!(value["extra"].get("areFeesSponsored").is_some());
    }

    #[test]
    fn payment_payload_matches_spec_example_field_for_field() {
        let parsed: PaymentPayload = serde_json::from_str(PAYMENT_PAYLOAD_JSON).unwrap();
        assert_eq!(parsed.x402_version, 2);
        assert_eq!(
            parsed.resource.as_ref().unwrap().url,
            "https://example.com/weather"
        );
        assert_eq!(parsed.accepted.scheme, "exact");
        assert!(parsed.payload.transaction.starts_with("AAAAAgAAAABriIN4"));

        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in ["x402Version", "resource", "accepted", "payload"] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
    }

    #[test]
    fn settlement_response_matches_spec_example_field_for_field() {
        let parsed: SettlementResponse = serde_json::from_str(SETTLEMENT_RESPONSE_JSON).unwrap();
        assert!(parsed.success);
        assert_eq!(parsed.transaction, "a1b2c3d4e5f6...");
        assert_eq!(parsed.network, "stellar:testnet");
        assert_eq!(
            parsed.payer.as_deref(),
            Some("GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU4APMDLQNBW5QV3W3KO")
        );
    }
}
