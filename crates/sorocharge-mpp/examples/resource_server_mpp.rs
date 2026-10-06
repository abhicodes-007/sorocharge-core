//! A local MPP `"stellar"`/`"charge"` resource server for end-to-end testing
//! against Stellar testnet. It issues a `WWW-Authenticate: Payment`
//! challenge at `/resource`, and on a retried request carrying an
//! `Authorization: Payment` credential it verifies and settles the payment
//! via `MppServer::settle_credential`, returning `200` with `Payment-Receipt`.
//!
//! This example owns the challenge store that `MppServer` deliberately
//! leaves to its caller: it maps each issued challenge id to the
//! `ChargeRequest` it was issued for, and consumes the entry on first use.
//!
//! Requires:
//!   SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY - funded `S...` seed; sponsors fees and is the payee
//!   SOROCHARGE_TESTNET_ASSET_CONTRACT         - SEP-41 SAC contract (`C...`)
//!   SOROCHARGE_TESTNET_AMOUNT                 - (optional) base units, default "1000000"
//!   SOROCHARGE_RESOURCE_BIND                  - (optional) default "127.0.0.1:8403"
//!   SOROCHARGE_TESTNET_RPC_URL                - (optional) default https://soroban-testnet.stellar.org
//!   SOROCHARGE_MPP_FEE_PAYER                  - (optional) "false" for unsponsored, client-paid fees; default sponsored
//!
//! Run with:
//!   cargo run --example resource_server_mpp -p sorocharge-mpp

use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use sorocharge_mpp::{
    ChargeRequest, Credential, MethodDetails, MppServer, MppServerConfig, Payload,
};
use sorocharge_signer::{Address, Signer, SorochargeError};
use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const REALM: &str = "localhost:8403";

struct KeypairSigner {
    signing_key: SigningKey,
    address: Address,
}

impl KeypairSigner {
    fn from_secret_seed(seed: &str) -> Self {
        let stellar_strkey::ed25519::PrivateKey(raw_seed) =
            stellar_strkey::ed25519::PrivateKey::from_string(seed)
                .expect("secret key must be a valid S... secret seed");
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

struct AppState {
    rpc: stellar_rpc_client::Client,
    signer: KeypairSigner,
    charge: ChargeRequest,
    /// Challenge id -> the request it was issued for. Entries are removed
    /// on first use, so a credential can only ever settle once.
    issued: Mutex<HashMap<String, (ChargeRequest, DateTime<Utc>)>>,
    /// Push-mode transaction hashes already settled. The spec requires a
    /// server to reject a hash it has consumed, even on a fresh challenge.
    consumed_hashes: Mutex<HashSet<String>>,
    counter: AtomicU64,
}

fn fresh_challenge_id(state: &AppState) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos() as u64;
    let n = state.counter.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}{:08x}", nanos, n)
}

fn issue_challenge(state: &AppState) -> Response {
    let id = fresh_challenge_id(state);
    let expires = Utc::now() + ChronoDuration::minutes(5);
    let server = MppServer::new(
        &state.rpc,
        &state.signer,
        NETWORK_PASSPHRASE.to_string(),
        MppServerConfig::default(),
    );
    let header = match server.build_challenge_header(&id, REALM, &state.charge, expires) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    state
        .issued
        .lock()
        .expect("challenge store poisoned")
        .insert(id, (state.charge.clone(), expires));

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&header).expect("challenge is a valid header value"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    (StatusCode::PAYMENT_REQUIRED, headers, "payment required\n").into_response()
}

/// Returns the credential sent in either the default `Authorization` header
/// or the alternate `Payment-Authorization` header.
fn credential_from_headers(headers: &HeaderMap) -> Option<Result<Credential, String>> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .or_else(|| headers.get("payment-authorization"))?
        .to_str()
        .ok()?;
    let encoded = raw.strip_prefix("Payment ")?;
    Some(
        BASE64URL
            .decode(encoded.trim())
            .map_err(|e| format!("base64url: {e}"))
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| format!("json: {e}"))),
    )
}

async fn resource(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let credential = match credential_from_headers(&headers) {
        None => return issue_challenge(&state),
        Some(Err(reason)) => {
            eprintln!("rejected malformed credential: {reason}");
            return issue_challenge(&state);
        }
        Some(Ok(c)) => c,
    };

    let entry = state
        .issued
        .lock()
        .expect("challenge store poisoned")
        .remove(&credential.challenge.id);
    let Some((expected, _expires)) = entry else {
        eprintln!("rejected credential for unknown or already-used challenge id");
        return issue_challenge(&state);
    };

    let server = MppServer::new(
        &state.rpc,
        &state.signer,
        NETWORK_PASSPHRASE.to_string(),
        MppServerConfig::default(),
    );
    let pushed_hash = match &credential.payload {
        Payload::Hash { hash } => Some(hash.clone()),
        Payload::Transaction { .. } => None,
    };
    let already_consumed = pushed_hash.as_ref().is_some_and(|h| {
        state
            .consumed_hashes
            .lock()
            .expect("hash store poisoned")
            .contains(h)
    });
    match server
        .settle_credential(&credential, &expected, Utc::now(), already_consumed)
        .await
    {
        Ok(receipt) => {
            if let Some(hash) = pushed_hash {
                state
                    .consumed_hashes
                    .lock()
                    .expect("hash store poisoned")
                    .insert(hash);
            }
            let encoded =
                BASE64URL.encode(serde_json::to_vec(&receipt).expect("serialize receipt"));
            let mut out = HeaderMap::new();
            out.insert(
                "payment-receipt",
                HeaderValue::from_str(&encoded).expect("receipt is a valid header value"),
            );
            (StatusCode::OK, out, "paid resource contents\n").into_response()
        }
        Err(e) => {
            eprintln!("settlement rejected: {e}");
            issue_challenge(&state)
        }
    }
}

#[tokio::main]
async fn main() {
    let facilitator_seed = env::var("SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY").expect(
        "set SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY to a funded testnet server's secret seed",
    );
    let asset = env::var("SOROCHARGE_TESTNET_ASSET_CONTRACT")
        .expect("set SOROCHARGE_TESTNET_ASSET_CONTRACT to a SEP-41 SAC contract address");
    let amount = env::var("SOROCHARGE_TESTNET_AMOUNT").unwrap_or_else(|_| "1000000".to_string());
    let bind =
        env::var("SOROCHARGE_RESOURCE_BIND").unwrap_or_else(|_| "127.0.0.1:8403".to_string());
    let rpc_url = env::var("SOROCHARGE_TESTNET_RPC_URL")
        .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string());
    let fee_payer = env::var("SOROCHARGE_MPP_FEE_PAYER")
        .map(|v| v != "false")
        .unwrap_or(true);

    let signer = KeypairSigner::from_secret_seed(&facilitator_seed);
    let charge = ChargeRequest {
        amount,
        currency: asset,
        recipient: signer.address().to_string(),
        description: Some("local test resource".to_string()),
        external_id: None,
        method_details: MethodDetails {
            network: "stellar:testnet".to_string(),
            fee_payer,
        },
    };

    let state = Arc::new(AppState {
        rpc: stellar_rpc_client::Client::new(&rpc_url).expect("invalid RPC URL"),
        signer,
        charge,
        issued: Mutex::new(HashMap::new()),
        consumed_hashes: Mutex::new(HashSet::new()),
        counter: AtomicU64::new(0),
    });

    let app = Router::new()
        .route("/resource", get(resource))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("failed to bind resource server address");
    println!("MPP resource server listening on http://{bind}/resource");
    axum::serve(listener, app).await.expect("server error");
}
