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
import { Address, Keypair, StrKey, xdr, nativeToScVal } from "@stellar/stellar-sdk";

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

function writeFixture(name, entry) {
  const fixture = {
    description: `${name}: unsigned SorobanAuthorizationEntry for a SEP-41 transfer`,
    sdk_version: "17.2.0",
    asset_contract: assetContract,
    payer,
    recipient,
    amount: amount.toString(),
    valid_until_ledger: validUntilLedger,
    nonce: nonce.toString(),
    unsigned_entry_xdr_base64: entry.toXdr("base64"),
  };
  const path = join(fixturesDir, `${name}.json`);
  writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`wrote ${path}`);
}

writeFixture("legacy_transfer", buildLegacyEntry());
