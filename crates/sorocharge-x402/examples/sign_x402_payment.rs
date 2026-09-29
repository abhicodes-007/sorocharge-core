//! Pays for an x402-protected resource on Stellar testnet.
//!
//! Requires:
//!   SOROCHARGE_TESTNET_SECRET_KEY - a funded testnet account's `S...` secret seed
//!   SOROCHARGE_X402_RESOURCE_URL  - the x402-protected resource URL to pay for
//!   SOROCHARGE_TESTNET_RPC_URL    - (optional) defaults to https://soroban-testnet.stellar.org
//!
//! Run with:
//!   cargo run --example sign_x402_payment -p sorocharge-x402
//!
//! This performs a real network call against whatever resource server is
//! named by SOROCHARGE_X402_RESOURCE_URL — see examples/verify_and_settle.rs
//! for a fully self-contained example that needs no counterparty server.

use std::env;
use std::time::Duration;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use sorocharge_signer::{Address, Signer, SorochargeError};
use sorocharge_x402::X402Client;
use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

/// A `Signer` backed by an in-memory ed25519 keypair, built from a Stellar
/// `S...` secret seed. `sorocharge-signer` never manages keys itself —
/// callers own signing, which is what this wrapper demonstrates.
struct KeypairSigner {
    signing_key: SigningKey,
    address: Address,
}

impl KeypairSigner {
    fn from_secret_seed(seed: &str) -> Self {
        let stellar_strkey::ed25519::PrivateKey(raw_seed) =
            stellar_strkey::ed25519::PrivateKey::from_string(seed)
                .expect("SOROCHARGE_TESTNET_SECRET_KEY must be a valid S... secret seed");
        let signing_key = SigningKey::from_bytes(&raw_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            public_key,
        ))));
        Self {
            signing_key,
            address,
        }
    }
}

impl Signer for KeypairSigner {
    fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
        Ok(self.signing_key.sign(preimage).to_bytes())
    }

    fn address(&self) -> Address {
        self.address.clone()
    }
}

#[tokio::main]
async fn main() {
    let secret_seed = env::var("SOROCHARGE_TESTNET_SECRET_KEY")
        .expect("set SOROCHARGE_TESTNET_SECRET_KEY to a funded testnet account's S... secret seed");
    let resource_url = env::var("SOROCHARGE_X402_RESOURCE_URL")
        .expect("set SOROCHARGE_X402_RESOURCE_URL to the x402-protected resource to pay for");
    let rpc_url = env::var("SOROCHARGE_TESTNET_RPC_URL")
        .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string());
    let network_passphrase = "Test SDF Network ; September 2015";

    let signer = KeypairSigner::from_secret_seed(&secret_seed);
    let rpc = stellar_rpc_client::Client::new(&rpc_url).expect("invalid RPC URL");
    let current_ledger = rpc
        .get_latest_ledger()
        .await
        .expect("getLatestLedger failed")
        .sequence;

    let client = X402Client::new(Duration::from_secs(30)).expect("failed to build HTTP client");

    println!("Paying for {resource_url} as {} ...", signer.address());
    let response = client
        .get_with_payment(&resource_url, &signer, network_passphrase, current_ledger)
        .await
        .expect("x402 payment flow failed");

    println!(
        "Resource server responded with status {}",
        response.status()
    );
    let body = response.text().await.expect("failed to read response body");
    println!("{body}");
}
