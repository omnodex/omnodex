# Contributing to Omnodex

We welcome contributions to Omnodex. Before you begin, please read this guide and the [development docs](DEVELOPMENT.md).

## Contributor License Agreement (CLA)

Omnodex is dual-licensed under the AGPL-3.0 and a separate commercial license. To maintain our ability to offer both licenses, all contributors must agree to the following CLA before their first contribution can be merged.

By submitting a pull request, you agree that:

1. **Your contribution is your original work**, or you have the right to submit it under the terms below.
2. **You grant Omnodex, LLC a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license** to use, reproduce, modify, distribute, sublicense, and otherwise exploit your contribution, in source and object form, under any license, including the AGPL-3.0 and the Omnodex commercial license.
3. **You retain copyright** to your contribution. This CLA does not transfer ownership - it grants Omnodex, LLC the additional rights needed for dual licensing.
4. **You understand** that your contribution will be publicly available under the AGPL-3.0, and may also be distributed under the Omnodex commercial license to customers who purchase one.
5. **You warrant** that your contribution does not knowingly infringe any third-party intellectual property rights.

This CLA is intentionally concise. If you have questions, open an issue or email [hello@omnodex.com](mailto:hello@omnodex.com).

A CLA-bot will automatically check your CLA status when you open a pull request. First-time contributors will be prompted to agree.

## How to contribute

1. Fork the repository and create a branch from `main`.
2. Make your changes. Add or update tests as appropriate.
3. Run the test suite: `node --test packages/*/test/**/*.test.mjs`
4. Ensure `npx tsc -b` compiles without errors.
5. Open a pull request against `main`.

See [DEVELOPMENT.md](DEVELOPMENT.md) for build commands, package layout, and architectural decisions. Full documentation is available at [docs.omnodex.com](https://docs.omnodex.com/).

## What to contribute

We're especially interested in:

- **New detection rules** - community rules that catch real-world agent security risks. See `packages/analyzer/src/rules/community/` for examples.
- **New interceptors** - support for additional AI agent platforms.
- **Bug fixes** - with a test that reproduces the bug.
- **Documentation improvements** - both in-repo docs and the docs site.

For larger changes, please open an issue first to discuss the approach.

## Code style

- TypeScript, strict mode.
- Tests use `node:test` with `.mjs` test files. Every new rule gets a dedicated test file with MUST_FIRE and MUST_NOT_FIRE cases.
- No external test frameworks or linters (yet).

## License

By contributing, you agree that your contributions are licensed under the terms described in the CLA above.

---

Copyright (c) 2026 Omnodex, LLC.
