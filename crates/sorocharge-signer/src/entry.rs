use stellar_xdr::{
    Int128Parts, InvokeContractArgs, ScAddress, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, VecM,
};

use crate::error::SorochargeError;

/// A Soroban account or contract address, as it appears inside XDR structures.
///
/// This is the same `ScAddress` the network itself uses, not a
/// library-specific wrapper: `sorocharge-signer` never re-encodes addresses
/// in a shape the reference SDKs don't also produce.
pub type Address = ScAddress;

/// The parameters of a single SEP-41 transfer this library will build, sign,
/// or verify an authorization entry for.
///
/// `amount` is `i128` base units (never a float) to match SEP-41's transfer
/// signature exactly, and `valid_until_ledger` is a ledger number (never
/// wall-clock time) because that is what Soroban authorization expiry
/// actually checks on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeParams {
    /// The SEP-41 Stellar Asset Contract (SAC) address being transferred.
    pub asset_contract: Address,
    /// The transfer amount, in the asset's base units.
    pub amount: i128,
    /// The address authorizing the transfer (the `from` of the SEP-41 `transfer`).
    pub payer: Address,
    /// The address receiving the transfer (the `to` of the SEP-41 `transfer`).
    pub recipient: Address,
    /// The last ledger sequence for which this authorization is valid.
    pub valid_until_ledger: u32,
}

/// Which `SorobanCredentials` shape a charge entry should be built and
/// signed for.
///
/// This mirrors `SorobanCredentialsType` one-for-one except for
/// `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`, which has no signature to build or
/// verify and so is out of scope for a payment-authorization library: every
/// charge here is authorized by an explicit `Address`, never implicitly by
/// the transaction's source account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialKind {
    /// `SOROBAN_CREDENTIALS_ADDRESS`: a single ed25519 signature over the
    /// legacy (pre-CAP-71) authorization preimage.
    Legacy,
    /// `SOROBAN_CREDENTIALS_ADDRESS_V2` (CAP-71): a single ed25519 signature
    /// over the address-bound authorization preimage. Mandatory from
    /// protocol 28 onward.
    AddressV2,
    /// `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71 delegated
    /// signers): the payer address's credential is satisfied by signatures
    /// from one or more delegate addresses instead of, or in addition to,
    /// the payer's own key.
    Delegated { signers: Vec<Address> },
}

/// A constructed `SorobanAuthorizationEntry` for a SEP-41 transfer, before it
/// carries a signature.
///
/// The credentials' `signature` field is the empty-vector placeholder
/// (`ScVal::Vec(Some(ScVec(..)))` with no elements) that `sign_entry` fills
/// in, matching the shape the reference SDK builds prior to signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedEntry(pub(crate) SorobanAuthorizationEntry);

impl UnsignedEntry {
    /// The wrapped `SorobanAuthorizationEntry`, for callers that need to
    /// inspect or serialize it directly (e.g. golden-vector tests).
    #[must_use]
    pub fn as_xdr(&self) -> &SorobanAuthorizationEntry {
        &self.0
    }
}

/// The empty-vector signature placeholder used before an entry is signed,
/// matching the reference SDK's own unsigned-entry convention
/// (`ScVal.scvVec([])`, not `scvVoid()`).
fn empty_signature_placeholder() -> ScVal {
    ScVal::Vec(Some(ScVec(VecM::default())))
}

/// Builds the `InvokeContractArgs` for a SEP-41 `transfer(from, to, amount)`
/// call, the single invocation every charge entry this library produces
/// authorizes.
fn build_transfer_invocation(
    params: &ChargeParams,
) -> Result<SorobanAuthorizedInvocation, SorochargeError> {
    let function_name =
        ScSymbol(
            "transfer"
                .try_into()
                .map_err(|_| SorochargeError::XdrEncodingFailed {
                    reason: "function name \"transfer\" does not fit SCSymbol".to_string(),
                })?,
        );
    let amount_parts = Int128Parts {
        hi: (params.amount >> 64) as i64,
        lo: (params.amount & (u64::MAX as i128)) as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(params.payer.clone()),
        ScVal::Address(params.recipient.clone()),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .map_err(|_| SorochargeError::XdrEncodingFailed {
        reason: "transfer args exceed SCVal array limit".to_string(),
    })?;
    let function = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
        contract_address: params.asset_contract.clone(),
        function_name,
        args,
    });
    Ok(SorobanAuthorizedInvocation {
        function,
        sub_invocations: VecM::default(),
    })
}

/// Generates a nonce with `getrandom`. The nonce only needs to be
/// unpredictable and unique per entry to prevent replay; it carries no
/// cryptographic weight of its own — the entry's signature is what the
/// network actually verifies.
fn random_nonce() -> Result<i64, SorochargeError> {
    let bits = getrandom::u64().map_err(|e| SorochargeError::XdrEncodingFailed {
        reason: format!("failed to generate nonce: {e}"),
    })?;
    Ok(bits as i64)
}

/// Builds an unsigned `SorobanAuthorizationEntry` authorizing a SEP-41
/// `transfer` for `params`, in the shape dictated by `credential`.
///
/// The nonce is generated internally with a fresh source of randomness on
/// every call — it exists to make each authorization unique, not to encode
/// caller-supplied state, so exposing it as a parameter would only invite
/// accidental reuse.
///
/// # Errors
///
/// Returns [`SorochargeError::UnsupportedCredentialType`] for a
/// `credential` this build of the library does not yet construct XDR for,
/// and [`SorochargeError::XdrEncodingFailed`] if a value can't be encoded
/// into its XDR-constrained shape (e.g. a `VecM` length limit).
pub fn build_charge_entry(
    params: &ChargeParams,
    credential: CredentialKind,
) -> Result<UnsignedEntry, SorochargeError> {
    let nonce = random_nonce()?;
    build_charge_entry_with_nonce(params, credential, nonce)
}

/// The deterministic core of [`build_charge_entry`], with the nonce taken as
/// an explicit argument rather than generated. Not part of the public API:
/// callers cannot control the nonce, but golden-vector tests need to pin it
/// to diff against a fixture generated with the same fixed nonce.
pub(crate) fn build_charge_entry_with_nonce(
    params: &ChargeParams,
    credential: CredentialKind,
    nonce: i64,
) -> Result<UnsignedEntry, SorochargeError> {
    let root_invocation = build_transfer_invocation(params)?;

    let credentials = match credential {
        CredentialKind::Legacy => {
            let address_credentials = SorobanAddressCredentials {
                address: params.payer.clone(),
                nonce,
                signature_expiration_ledger: params.valid_until_ledger,
                signature: empty_signature_placeholder(),
            };
            SorobanCredentials::Address(address_credentials)
        }
        CredentialKind::AddressV2 | CredentialKind::Delegated { .. } => {
            return Err(SorochargeError::UnsupportedCredentialType);
        }
    };

    Ok(UnsignedEntry(SorobanAuthorizationEntry {
        credentials,
        root_invocation,
    }))
}

#[cfg(test)]
mod golden_vector_tests {
    use super::*;
    use serde::Deserialize;
    use stellar_xdr::{Limits, ReadXdr, WriteXdr};

    /// Diffs `build_charge_entry`'s XDR output against a fixture generated
    /// from the pinned `@stellar/stellar-sdk` (see
    /// `tests/golden_vectors/generate.mjs` at the repo root). A signing
    /// library that "looks right" but hasn't been byte-diffed against the
    /// reference implementation is not done.
    #[derive(Deserialize)]
    struct Fixture {
        asset_contract: String,
        payer: String,
        recipient: String,
        amount: String,
        valid_until_ledger: u32,
        nonce: String,
        unsigned_entry_xdr_base64: String,
    }

    fn load_fixture(name: &str) -> Fixture {
        let path = format!(
            "{}/../../tests/golden_vectors/fixtures/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"));
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse fixture {path}: {e}"))
    }

    #[test]
    fn legacy_transfer_matches_reference_sdk_byte_for_byte() {
        let fixture = load_fixture("legacy_transfer");

        let params = ChargeParams {
            asset_contract: fixture.asset_contract.parse::<ScAddress>().unwrap(),
            amount: fixture.amount.parse().unwrap(),
            payer: fixture.payer.parse::<ScAddress>().unwrap(),
            recipient: fixture.recipient.parse::<ScAddress>().unwrap(),
            valid_until_ledger: fixture.valid_until_ledger,
        };
        let nonce: i64 = fixture.nonce.parse().unwrap();

        let unsigned = build_charge_entry_with_nonce(&params, CredentialKind::Legacy, nonce)
            .expect("build_charge_entry_with_nonce should succeed for legacy credentials");

        let expected = SorobanAuthorizationEntry::from_xdr_base64(
            &fixture.unsigned_entry_xdr_base64,
            Limits::none(),
        )
        .expect("fixture XDR should decode");

        let actual_bytes = unsigned
            .as_xdr()
            .to_xdr(Limits::none())
            .expect("constructed entry should encode to XDR");
        let expected_bytes = expected
            .to_xdr(Limits::none())
            .expect("decoded fixture should re-encode to XDR");

        assert_eq!(
            actual_bytes, expected_bytes,
            "sorocharge-signer's unsigned entry XDR must be byte-identical to @stellar/stellar-sdk 17.2.0's output"
        );
    }
}
