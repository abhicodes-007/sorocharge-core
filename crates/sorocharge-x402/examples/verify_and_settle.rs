//! A fully self-contained x402 round trip on Stellar testnet: builds and
//! signs a payment exactly as a payer's client would, then runs it through
//! a facilitator's `verify` and `settle` exactly as a facilitator would —
//! with no counterparty resource server needed, since this example plays
//! both roles itself.
//!
//! Requires:
//!   SOROCHARGE_TESTNET_PAYER_SECRET_KEY       - funded payer account's `S...` secret seed
//!   SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY - funded facilitator/fee-sponsor account's `S...` secret seed
//!   SOROCHARGE_TESTNET_ASSET_CONTRACT         - a SEP-41 SAC contract address (`C...`) the payer holds a balance of
//!   SOROCHARGE_TESTNET_AMOUNT                 - (optional) base units to transfer, defaults to "1"
//!   SOROCHARGE_TESTNET_RPC_URL                - (optional) defaults to https://soroban-testnet.stellar.org
//!
//! The facilitator account is also the payment's recipient here, purely to
//! keep this example to two funded keys instead of three; nothing about
//! sorocharge-x402 requires that.
//!
//! Run with:
//!   cargo run --example verify_and_settle -p sorocharge-x402
//!
//! This submits a real transaction on Stellar testnet if both accounts are
//! funded and the payer holds the named asset.

use std::env;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use sorocharge_signer::{
    build_charge_entry, sign_entry, Address, ChargeParams, CredentialKind, Signer, SorochargeError,
};
use sorocharge_x402::{
    Facilitator, FacilitatorConfig, PaymentPayload, PaymentRequirements, StellarExtra,
    StellarPayload, VerifyRequest,
};
use stellar_xdr::{
    AccountId, HostFunction, Int128Parts, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ScAddress, ScSymbol, ScVal,
    SequenceNumber, SorobanAuthorizationEntry, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

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

/// Builds the same all-zeros-source, single-invokeHostFunction transaction
/// envelope `sorocharge_x402::X402Client` builds internally. Reproduced
/// here (rather than imported) because that construction is a private
/// implementation detail of the client — this example shows what a client
/// produces, using only sorocharge-signer's public API plus raw XDR types.
fn build_payment_envelope(
    params: &ChargeParams,
    signed_entry: &sorocharge_signer::SignedEntry,
) -> TransactionEnvelope {
    let function_name = ScSymbol("transfer".try_into().unwrap());
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
    .unwrap();
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: params.asset_contract.clone(),
        function_name,
        args,
    });
    let auth: VecM<SorobanAuthorizationEntry> =
        vec![signed_entry.as_xdr().clone()].try_into().unwrap();
    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth,
        }),
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 0,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
}

#[tokio::main]
async fn main() {
    let payer_seed = env::var("SOROCHARGE_TESTNET_PAYER_SECRET_KEY")
        .expect("set SOROCHARGE_TESTNET_PAYER_SECRET_KEY to a funded testnet payer's secret seed");
    let facilitator_seed = env::var("SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY").expect(
        "set SOROCHARGE_TESTNET_FACILITATOR_SECRET_KEY to a funded testnet facilitator's secret seed",
    );
    let asset_contract_str = env::var("SOROCHARGE_TESTNET_ASSET_CONTRACT")
        .expect("set SOROCHARGE_TESTNET_ASSET_CONTRACT to a SEP-41 SAC contract address");
    let amount_str = env::var("SOROCHARGE_TESTNET_AMOUNT").unwrap_or_else(|_| "1".to_string());
    let rpc_url = env::var("SOROCHARGE_TESTNET_RPC_URL")
        .unwrap_or_else(|_| "https://soroban-testnet.stellar.org".to_string());
    let network_passphrase = "Test SDF Network ; September 2015";

    let payer = KeypairSigner::from_secret_seed(&payer_seed);
    let facilitator_signer = KeypairSigner::from_secret_seed(&facilitator_seed);
    let rpc = stellar_rpc_client::Client::new(&rpc_url).expect("invalid RPC URL");

    let current_ledger = rpc
        .get_latest_ledger()
        .await
        .expect("getLatestLedger failed")
        .sequence;

    let params = ChargeParams {
        asset_contract: asset_contract_str
            .parse()
            .expect("SOROCHARGE_TESTNET_ASSET_CONTRACT must be a valid C... address"),
        amount: amount_str
            .parse()
            .expect("SOROCHARGE_TESTNET_AMOUNT must be an integer"),
        payer: payer.address(),
        recipient: facilitator_signer.address(),
        valid_until_ledger: current_ledger + 200,
    };

    println!(
        "Building a payment of {} base units from {} to {} ...",
        params.amount, params.payer, params.recipient
    );
    let unsigned =
        build_charge_entry(&params, CredentialKind::Legacy).expect("failed to build charge entry");
    let signed = sign_entry(unsigned, &payer, network_passphrase).expect("failed to sign entry");
    let envelope = build_payment_envelope(&params, &signed);
    let transaction = envelope
        .to_xdr_base64(Limits::none())
        .expect("failed to encode transaction envelope");

    let requirements = PaymentRequirements {
        scheme: "exact".to_string(),
        network: "stellar:testnet".to_string(),
        amount: amount_str.clone(),
        asset: asset_contract_str.clone(),
        pay_to: params.recipient.to_string(),
        max_timeout_seconds: 60,
        extra: StellarExtra {
            are_fees_sponsored: true,
        },
    };
    let request = VerifyRequest {
        x402_version: 2,
        payment_payload: PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: requirements.clone(),
            payload: StellarPayload { transaction },
            extensions: serde_json::Map::new(),
        },
        payment_requirements: requirements,
    };

    let facilitator = Facilitator::new(
        &rpc,
        &facilitator_signer,
        network_passphrase.to_string(),
        FacilitatorConfig::default(),
    );

    println!("Verifying ...");
    let verify_response = facilitator
        .verify(&request)
        .await
        .expect("facilitator.verify itself failed (not the same as an invalid payment)");
    println!("{verify_response:?}");
    if !verify_response.is_valid {
        eprintln!("payment did not verify; not attempting settlement");
        std::process::exit(1);
    }

    println!("Settling (this submits a real testnet transaction) ...");
    let settlement_response = facilitator
        .settle(&request)
        .await
        .expect("facilitator.settle itself failed");
    println!("{settlement_response:?}");
}
