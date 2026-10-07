# Contributing to sorocharge-core

Thanks for helping. This is a signing library for payment authorization
entries — changes here move money, so the bar is "would I trust this with
my own funds?" Read [`CLAUDE.md`](CLAUDE.md) for the full engineering
contract; this file is the part that matters for landing a pull request.

## Ground rules

1. **Never bulk-stage after the initial scaffold commit** — name files
   explicitly in `git add`.
2. **One commit per logical unit** — one function, one type file, one test
   block. A commit that does two unrelated things gets asked to split.
3. **Push immediately after every commit** — never batch local history into
   a single push.
4. **Conventional commits**: `type(scope): description`, lowercase,
   imperative. Scopes in use: `signer`, `x402`, `mpp`, `ci`, `docs`,
   `tests`, `fixtures`.
5. **Never force-push or rewrite pushed history.** There are no exceptions.
6. **Never commit a secret, test seed phrase, or funded testnet key.** Not
   even in fixtures — golden vectors are byte strings, not keys.

## Golden vectors are the contract

`sorocharge-signer` proves every XDR it produces is byte-identical to the
pinned `@stellar/stellar-sdk` by diffing against fixtures in
[`tests/golden_vectors/`](tests/golden_vectors) in CI. A change that alters
bytes the reference SDK would not produce is wrong, no matter how clean the
code looks. If you change what gets signed or how it is encoded, regenerate
the vectors from the pinned SDK — never hand-edit them, never regenerate
with a different SDK version.

## Workflow

```sh
cargo test --workspace      # what CI runs, locally
cargo clippy --workspace --all-targets -- -D warnings
```

1. Fork and branch from `main`: `git checkout -b fix/<short-slug>`.
2. Make the change. Tests accompany behavior changes — a bug fix lands with
   a test that fails without it.
3. Run the checks above before every push.
4. Open a pull request against `main` with: what was broken (or missing),
   how it's fixed, how you verified it. Reference the issue with
   `Fixes #N`.
5. Respond to review comments; CI failures are yours to fix.

Keep pull requests focused. One concern per PR — a refactor mixed into a
bug fix makes both harder to review.

## Where to start

Issues labeled [`good first issue`](https://github.com/sorocharge/sorocharge-core/issues?q=label%3A%22good+first+issue%22)
are scoped to be reviewable in one sitting. Comment on the issue before
claiming it so nobody duplicates work.

## Reporting bugs

Open an issue with: the call you made, what you expected, what happened,
and the crate versions (`cargo tree` fragment is fine). Security issues do
**not** go in public issues — see [`SECURITY.md`](SECURITY.md).
