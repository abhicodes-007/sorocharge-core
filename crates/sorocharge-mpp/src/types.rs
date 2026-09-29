//! JSON wire types for MPP's `draft-stellar-charge-00`, layered on the base
//! `draft-httpauth-payment-01` auth scheme and `draft-payment-intent-charge-00`
//! charge intent (all in `tempoxyz/mpp-specs`). Field names and shapes are
//! copied verbatim from those specs, not inferred.

use serde::{Deserialize, Serialize};

/// The Stellar-specific `methodDetails` object inside a charge request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MethodDetails {
    /// CAIP-2 Stellar chain identifier: `"stellar:pubnet"` or `"stellar:testnet"`.
    pub network: String,
    /// If `true`, the server sponsors transaction fees (pull mode only).
    #[serde(default)]
    pub fee_payer: bool,
}

/// The `request` object carried (base64url + JCS-encoded) in a challenge's
/// `request` auth-param: the shared "charge" intent fields plus Stellar's
/// `methodDetails`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChargeRequest {
    /// Stringified non-negative integer, SEP-41 base units.
    pub amount: String,
    /// The SEP-41 token contract address (`C...`).
    pub currency: String,
    /// The recipient's Stellar account address (`G...`).
    pub recipient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub method_details: MethodDetails,
}

/// The challenge auth-params, as echoed in a credential's `challenge`
/// object. `request` here is the still-encoded base64url string, not the
/// decoded `ChargeRequest` — the credential must echo it byte-for-byte for
/// challenge-binding verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// The Stellar-specific `payload` of a credential, keyed by `type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Payload {
    /// Pull mode (default): a base64-encoded `TransactionEnvelope`.
    Transaction { transaction: String },
    /// Push mode (fallback): a 64-character hex transaction hash, for a
    /// transaction the client already broadcast itself.
    Hash { hash: String },
}

/// The full credential sent in the `Authorization` (or
/// `Payment-Authorization`) header, base64url-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    pub challenge: Challenge,
    pub payload: Payload,
    /// The payer's identity, recommended as a `did:pkh` DID, e.g.
    /// `did:pkh:stellar:testnet:GABC...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The `Payment-Receipt` header payload on a successful settlement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Always `"stellar"`.
    pub method: String,
    /// The settled transaction hash.
    pub reference: String,
    /// Always `"success"` — receipts are only issued on success.
    pub status: String,
    /// RFC 3339 settlement timestamp.
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `draft-stellar-charge-00`'s `methodDetails` example.
    const CHARGE_REQUEST_JSON: &str = r#"
    {
      "amount": "10000000",
      "currency": "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4W",
      "recipient": "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU",
      "description": "API access fee",
      "methodDetails": {
        "network": "stellar:testnet",
        "feePayer": true
      }
    }
    "#;

    /// Verbatim from the same spec's pull-mode "Transaction Payload" example.
    const CREDENTIAL_JSON: &str = r#"
    {
      "challenge": {
        "id": "kM9xPqWvT2nJrHsY4aDfEb",
        "realm": "api.example.com",
        "method": "stellar",
        "intent": "charge",
        "request": "eyJ...",
        "expires": "2025-02-05T12:05:00Z"
      },
      "payload": {
        "type": "transaction",
        "transaction": "AAAAAgAAAABriIN4..."
      },
      "source": "did:pkh:stellar:testnet:GABC..."
    }
    "#;

    /// Verbatim from the same spec's push-mode "Hash Payload" example.
    const HASH_CREDENTIAL_JSON: &str = r#"
    {
      "challenge": {
        "id": "pT7yHnKmQ2wErXsZ5vCbNl",
        "realm": "api.example.com",
        "method": "stellar",
        "intent": "charge",
        "request": "eyJ...",
        "expires": "2025-02-05T12:05:00Z"
      },
      "payload": {
        "type": "hash",
        "hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"
      },
      "source": "did:pkh:stellar:testnet:GABC..."
    }
    "#;

    #[test]
    fn charge_request_matches_spec_example_field_for_field() {
        let parsed: ChargeRequest = serde_json::from_str(CHARGE_REQUEST_JSON).unwrap();
        assert_eq!(parsed.amount, "10000000");
        assert_eq!(parsed.currency, "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4W");
        assert_eq!(parsed.recipient, "GBHEGW3KWOY2OFH767EDALFGCUTBOEVBDQMCKU");
        assert_eq!(parsed.description.as_deref(), Some("API access fee"));
        assert_eq!(parsed.method_details.network, "stellar:testnet");
        assert!(parsed.method_details.fee_payer);

        let value: serde_json::Value = serde_json::to_value(&parsed).unwrap();
        for key in [
            "amount",
            "currency",
            "recipient",
            "description",
            "methodDetails",
        ] {
            assert!(
                value.get(key).is_some(),
                "missing field {key} after round-trip"
            );
        }
        assert!(value["methodDetails"].get("feePayer").is_some());
    }

    #[test]
    fn transaction_credential_matches_spec_example_field_for_field() {
        let parsed: Credential = serde_json::from_str(CREDENTIAL_JSON).unwrap();
        assert_eq!(parsed.challenge.id, "kM9xPqWvT2nJrHsY4aDfEb");
        assert_eq!(parsed.challenge.method, "stellar");
        assert_eq!(parsed.challenge.intent, "charge");
        assert_eq!(
            parsed.source.as_deref(),
            Some("did:pkh:stellar:testnet:GABC...")
        );
        match parsed.payload {
            Payload::Transaction { transaction } => {
                assert!(transaction.starts_with("AAAAAgAAAABriIN4"));
            }
            Payload::Hash { .. } => panic!("expected a transaction payload"),
        }
    }

    #[test]
    fn hash_credential_matches_spec_example_field_for_field() {
        let parsed: Credential = serde_json::from_str(HASH_CREDENTIAL_JSON).unwrap();
        match parsed.payload {
            Payload::Hash { hash } => {
                assert_eq!(hash.len(), 64);
            }
            Payload::Transaction { .. } => panic!("expected a hash payload"),
        }
    }
}
