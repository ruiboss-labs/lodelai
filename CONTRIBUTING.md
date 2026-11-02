# Contributing to lodelai

Thanks for helping. This guide is short on purpose.

## Before you start

- **Bugs and small fixes** — open a pull request directly.
- **New features or protocol changes** — open an issue first, so we can agree on the shape before you write code.
- **Security issues** — don't open an issue. See [SECURITY.md](SECURITY.md).

## Sign off your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org) instead of a CLA. Add a `Signed-off-by` line to every commit:

```sh
git commit -s -m "fix(relay): reject empty device lists"
```

This certifies that you wrote the change, or have the right to submit it under the project's licenses. Pull requests with unsigned commits can't be merged.

## Run the checks

There's no hosted CI yet, so please run these before you open a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

If you changed a schema in `packages/protocol/schema/`, regenerate the types and commit them:

```sh
cargo run -p lodelai-protocol-gen
bun run --filter @lodelai/protocol gen
bunx biome format --write packages/protocol
```

## Pull requests

- One change per pull request, with tests when behavior changes.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org): `feat(relay): …`, `fix(crypto): …`, `docs: …`.
- Describe what changed and why. Link the issue if there is one.
- Keep protocol changes backward compatible, or say clearly in the description that they aren't.

## How your change ships

For now, a private monorepo is the source of truth, and each release is exported here. When we accept your pull request, we bring it into the monorepo with your `Signed-off-by` and `Co-authored-by` lines intact, and it appears here in the next release. Your pull request is closed with a link to that release.

## License of contributions

Your contribution is licensed under the license of the directory it lands in: AGPL-3.0 for `services/relay` and `deploy/relay`, Apache-2.0 for everything else. See [LICENSING.md](LICENSING.md).
