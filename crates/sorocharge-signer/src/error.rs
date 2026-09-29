use core::fmt;

/// Every failure `sorocharge-signer` can produce.
///
/// Each variant names one specific, actionable failure so a caller (or a
/// test) can tell exactly which check failed rather than pattern-matching on
/// a string. No variant collapses distinct failures into a catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SorochargeError {
    /// A strkey (`G...`, `C...`, `M...`) failed to decode into an `ScAddress`.
    InvalidAddress { strkey: String },
    /// The credential's XDR shape does not match any variant this library
    /// signs or verifies (e.g. a future `SorobanCredentialsType` arm).
    UnsupportedCredentialType,
    /// `Delegated` was constructed with no signers, which can never satisfy
    /// `__check_auth`.
    EmptyDelegateSigners,
    /// `Delegated` named the same address as a delegate signer more than
    /// once, which CAP-71-01 forbids (the host rejects the entry).
    DuplicateDelegateSigner,
    /// The entry's `valid_until_ledger` has already passed `current_ledger`.
    ExpiredEntry {
        valid_until_ledger: u32,
        current_ledger: u32,
    },
    /// The entry's invocation is not a SEP-41 `transfer(from, to, amount)`
    /// call on a single contract, so there is nothing meaningful to compare
    /// its asset/payer/amount/recipient against.
    UnexpectedInvocationShape,
    /// The entry's asset contract does not match `ChargeParams::asset_contract`.
    AssetMismatch,
    /// The entry's authorizing address does not match `ChargeParams::payer`.
    PayerMismatch,
    /// The entry's amount does not match `ChargeParams::amount` exactly.
    AmountMismatch,
    /// The entry's recipient does not match `ChargeParams::recipient`.
    RecipientMismatch,
    /// The signature does not verify against the reconstructed preimage.
    InvalidSignature,
    /// A signer's address matches no credential node (top-level address or
    /// delegate) in the entry being signed.
    NoMatchingCredentialNode,
    /// The `Signer` implementation returned an error while signing a preimage.
    SigningFailed { reason: String },
    /// Constructing or serializing an XDR structure failed.
    XdrEncodingFailed { reason: String },
}

impl fmt::Display for SorochargeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress { strkey } => {
                write!(f, "invalid strkey address: {strkey}")
            }
            Self::UnsupportedCredentialType => {
                write!(f, "unsupported Soroban credential type")
            }
            Self::EmptyDelegateSigners => {
                write!(f, "delegated credential requires at least one signer")
            }
            Self::DuplicateDelegateSigner => {
                write!(f, "delegated credential lists the same signer address more than once")
            }
            Self::ExpiredEntry {
                valid_until_ledger,
                current_ledger,
            } => write!(
                f,
                "entry expired: valid until ledger {valid_until_ledger}, current ledger {current_ledger}"
            ),
            Self::UnexpectedInvocationShape => write!(
                f,
                "entry does not authorize a single SEP-41 transfer(from, to, amount) call"
            ),
            Self::AssetMismatch => write!(f, "asset contract does not match expected charge"),
            Self::PayerMismatch => write!(f, "authorizing address does not match expected payer"),
            Self::AmountMismatch => write!(f, "amount does not match expected charge"),
            Self::RecipientMismatch => write!(f, "recipient does not match expected charge"),
            Self::InvalidSignature => write!(f, "signature is invalid for the entry's credential"),
            Self::NoMatchingCredentialNode => write!(
                f,
                "signer's address matches no credential node in this entry"
            ),
            Self::SigningFailed { reason } => write!(f, "signing failed: {reason}"),
            Self::XdrEncodingFailed { reason } => write!(f, "XDR encoding failed: {reason}"),
        }
    }
}

impl std::error::Error for SorochargeError {}
