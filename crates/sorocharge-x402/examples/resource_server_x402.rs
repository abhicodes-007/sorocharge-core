//! A local x402 resource server for end-to-end testing against Stellar
//! testnet. It serves a `402 Payment Required` challenge at `/resource`,
//! and on a retried request carrying `PAYMENT-SIGNATURE` it verifies and
//! settles the payment through the in-process `Facilitator`, returning `200`
//! with `PAYMENT-RESPONSE` on success.
//!
//! Requires:
//!   SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY - funded `S...` seed; sponsors fees and is the payTo
//!   SOROCHARGE_TESTNET_ASSET_CONTRACT         - SEP-41 SAC contract (`C...`)
//!   SOROCHARGE_TESTNET_AMOUNT                 - (optional) base units, default "1000000"
//!   SOROCHARGE_RESOURCE_BIND                  - (optional) default "127.0.0.1:8402"
//!   SOROCHARGE_TESTNET_RPC_URL                - (optional) default https://soroban-testnet.stellar.org
//!
//! Run with:
//!   cargo run --example resource_server_x402 -p sorocharge-x402
//! then, in another shell, pay for it:
//!   SOROCHARGE_X402_RESOURCE_URL=http://127.0.0.1:8402/resource \
//!   cargo run --example sign_x402_payment -p sorocharge-x402

use std::env;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use sorocharge_signer::{Address, Signer, SorochargeError};
use sorocharge_x402::{
    Facilitator, FacilitatorConfig, PaymentPayload, PaymentRequired, PaymentRequirements,
    ResourceInfo, SettlementResponse, StellarExtra, VerifyRequest,
};
use stellar_xdr::{AccountId, PublicKey, ScAddress, Uint256};

const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
const PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
const PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

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
    requirements: PaymentRequirements,
    resource: ResourceInfo,
}

fn challenge(state: &AppState, error: Option<&str>) -> Response {
    let required = PaymentRequired {
        x402_version: 2,
        error: error.map(str::to_string),
        resource: state.resource.clone(),
        accepts: vec![state.requirements.clone()],
        extensions: serde_json::Map::new(),
    };
    let encoded = BASE64.encode(serde_json::to_vec(&required).expect("serialize PaymentRequired"));
    let mut headers = HeaderMap::new();
    headers.insert(
        PAYMENT_REQUIRED,
        HeaderValue::from_str(&encoded).expect("base64 is a valid header value"),
    );
    (StatusCode::PAYMENT_REQUIRED, headers).into_response()
}

async fn resource(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(header) = headers.get(PAYMENT_SIGNATURE) else {
        return challenge(&state, Some("PAYMENT-SIGNATURE header is required"));
    };
    let decoded = header
        .to_str()
        .ok()
        .and_then(|v| BASE64.decode(v).ok())
        .and_then(|b| serde_json::from_slice::<PaymentPayload>(&b).ok());
    let Some(payment_payload) = decoded else {
        return challenge(
            &state,
            Some("PAYMENT-SIGNATURE is not a valid payment payload"),
        );
    };

    let request = VerifyRequest {
        x402_version: 2,
        payment_payload,
        payment_requirements: state.requirements.clone(),
    };
    let facilitator = Facilitator::new(
        &state.rpc,
        &state.signer,
        NETWORK_PASSPHRASE.to_string(),
        FacilitatorConfig::default(),
    );

    let verdict = match facilitator.verify(&request).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !verdict.is_valid {
        return challenge(&state, verdict.invalid_reason.as_deref());
    }

    let settlement: SettlementResponse = match facilitator.settle(&request).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !settlement.success {
        return challenge(&state, settlement.error_reason.as_deref());
    }

    let receipt = BASE64.encode(serde_json::to_vec(&settlement).expect("serialize settlement"));
    let mut out = HeaderMap::new();
    out.insert(
        PAYMENT_RESPONSE,
        HeaderValue::from_str(&receipt).expect("base64 is a valid header value"),
    );
    (StatusCode::OK, out, "paid resource contents\n").into_response()
}

#[tokio::main]
async fn main() {
    let facilitator_seed = env::var("SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY").expect(
        "set SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY to a funded testnet facilitator's secret seed",
    );
    let asset = env::var("SOROCHARGE_TESTNET_ASSET_CONTRACT")
        .expect("set SOROCHARGE_TESTNET_ASSET_CONTRACT to a SEP-41 SAC contract address");
    let amount = env::var("SOROCHARGE_TESTNET_AMOUNT").unwrap_or_else(|_| "1000000".to_string());
    let bind =
        env::var("SOROCHARGE_RESOURCE_BIND").unwrap_or_else(|_| "127.0.0.1:8402".to_string());
    let rpc_url = env::var("SOROCHARGE_TESTNET_RPC_URL")
        .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string());

    let signer = KeypairSigner::from_secret_seed(&facilitator_seed);
    let pay_to = signer.address().to_string();
    let state = Arc::new(AppState {
        rpc: stellar_rpc_client::Client::new(&rpc_url).expect("invalid RPC URL"),
        requirements: PaymentRequirements {
            scheme: "exact".to_string(),
            network: "stellar:testnet".to_string(),
            amount,
            asset,
            pay_to,
            max_timeout_seconds: 60,
            extra: StellarExtra {
                are_fees_sponsored: true,
            },
        },
        resource: ResourceInfo {
            url: format!("http://{bind}/resource"),
            description: Some("local test resource".to_string()),
            mime_type: Some("text/plain".to_string()),
        },
        signer,
    });

    let app = Router::new()
        .route("/resource", get(resource))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("failed to bind resource server address");
    println!("x402 resource server listening on http://{bind}/resource");
    axum::serve(listener, app).await.expect("server error");
}
