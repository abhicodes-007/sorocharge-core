// Generates golden-vector fixtures from the pinned @stellar/stellar-sdk
// (see package.json for the exact version) and writes them to fixtures/*.json.
// sorocharge-signer's Rust tests diff their own XDR output against these
// fixtures byte-for-byte; this script is dev-only tooling, never a runtime
// dependency of the Rust crates.
//
// All inputs below (keys, amounts, ledger, nonce) are fixed rather than
// randomly generated so this script produces byte-identical output on every
// run, which is what lets CI regenerate the fixtures and diff them against
// what's committed.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Address,
  Keypair,
  Networks,
  StrKey,
  xdr,
  nativeToScVal,
  authorizeEntry,
  buildWithDelegatesEntry,
} from "@stellar/stellar-sdk";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, "fixtures");
mkdirSync(fixturesDir, { recursive: true });

function fixedSeed(byte) {
  return Buffer.alloc(32, byte);
}

const payerKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x11));
const recipientKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x22));
const payer = payerKeypair.publicKey();
const recipient = recipientKeypair.publicKey();
const assetContract = StrKey.encodeContract(fixedSeed(0x33));

const amount = 1000000000n; // 100.0000000 units of a 7-decimal SEP-41 asset
const validUntilLedger = 123456;
const nonce = 42n; // fixed for reproducibility; a real client uses a random nonce

function buildTransferInvocation() {
  const invokeArgs = new xdr.InvokeContractArgs({
    contractAddress: new Address(assetContract).toScAddress(),
    functionName: "transfer",
    args: [
      nativeToScVal(payer, { type: "address" }),
      nativeToScVal(recipient, { type: "address" }),
      nativeToScVal(amount, { type: "i128" }),
    ],
  });

  return new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        invokeArgs,
      ),
    subInvocations: [],
  });
}

function buildLegacyEntry() {
  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVec([]),
  });

  return new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials),
    rootInvocation: buildTransferInvocation(),
  });
}

function buildAddressV2Entry() {
  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVec([]),
  });

  return new xdr.SorobanAuthorizationEntry({
    credentials:
      xdr.SorobanCredentials.sorobanCredentialsAddressV2(addressCredentials),
    rootInvocation: buildTransferInvocation(),
  });
}

function buildDelegatedEntry() {
  const delegateAKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x44));
  const delegateBKeypair = Keypair.fromRawEd25519Seed(fixedSeed(0x55));

  const addressCredentials = new xdr.SorobanAddressCredentials({
    address: new Address(payer).toScAddress(),
    nonce,
    signatureExpirationLedger: validUntilLedger,
    signature: xdr.ScVal.scvVoid(),
  });

  // Passed out of address order on purpose to exercise
  // buildWithDelegatesEntry's own ascending sort by address.
  const delegates = [
    { address: delegateBKeypair.publicKey() },
    { address: delegateAKeypair.publicKey() },
  ];

  const entryWithoutDelegates = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(addressCredentials),
    rootInvocation: buildTransferInvocation(),
  });

  const entry = buildWithDelegatesEntry({
    entry: entryWithoutDelegates,
    validUntilLedgerSeq: validUntilLedger,
    delegates,
  });

  return { entry, delegateA: delegateAKeypair.publicKey(), delegateB: delegateBKeypair.publicKey() };
}

function writeFixture(name, entry, extra = {}, xdrField = "unsigned_entry_xdr_base64") {
  const fixture = {
    description: `${name}: a SorobanAuthorizationEntry for a SEP-41 transfer`,
    sdk_version: "17.2.0",
    asset_contract: assetContract,
    payer,
    recipient,
    amount: amount.toString(),
    valid_until_ledger: validUntilLedger,
    nonce: nonce.toString(),
    ...extra,
    [xdrField]: entry.toXdr("base64"),
  };
  const path = join(fixturesDir, `${name}.json`);
  writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`wrote ${path}`);
}

writeFixture("legacy_transfer", buildLegacyEntry());
writeFixture("address_v2_transfer", buildAddressV2Entry());

const delegated = buildDelegatedEntry();
writeFixture("delegated_transfer", delegated.entry, {
  // Listed out of sort order on purpose; the fixture's XDR reflects the
  // sorted order buildWithDelegatesEntry actually produced.
  delegate_signers: [delegated.delegateB, delegated.delegateA],
});

const networkPassphrase = Networks.TESTNET;
const signedLegacyEntry = await authorizeEntry(
  buildLegacyEntry(),
  payerKeypair,
  validUntilLedger,
  networkPassphrase,
);
writeFixture(
  "legacy_transfer_signed",
  signedLegacyEntry,
  { network_passphrase: networkPassphrase },
  "signed_entry_xdr_base64",
);
