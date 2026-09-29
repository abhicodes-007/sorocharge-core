//! Mapping between Stellar network passphrases and the CAIP-2 identifiers
//! (`stellar:pubnet` / `stellar:testnet`) `draft-stellar-charge-00` uses.

use crate::error::MppError;

pub const PUBNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// The CAIP-2 identifier for a network passphrase.
///
/// # Errors
///
/// Returns [`MppError::UnsupportedNetwork`] for any passphrase other than
/// mainnet's or testnet's.
pub fn caip2_for_passphrase(network_passphrase: &str) -> Result<&'static str, MppError> {
    match network_passphrase {
        PUBNET_PASSPHRASE => Ok("stellar:pubnet"),
        TESTNET_PASSPHRASE => Ok("stellar:testnet"),
        other => Err(MppError::UnsupportedNetwork {
            network: other.to_string(),
        }),
    }
}
