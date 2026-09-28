use stellar_xdr::ScAddress;

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
