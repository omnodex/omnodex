# Contributing to Omnodex

We welcome contributions to Omnodex. Before you begin, please read this guide and the [development docs](DEVELOPMENT.md).

## Contributor License Agreement (CLA)

Omnodex is dual-licensed under the AGPL-3.0 and a separate commercial license. To maintain our ability to offer both licenses, all contributors must agree to the following CLA before their first contribution can be merged.

In this CLA, "Omnodex" means Omnodex, LLC and its successors and assigns. By submitting a pull request, you agree that:

1. **Your contribution is your original work**, except for any third-party material you identify under item 6, and you have the right to submit it under the terms below.
2. **You grant Omnodex a perpetual, worldwide, non-exclusive, royalty-free, irrevocable copyright license** to use, reproduce, modify, distribute, sublicense, and otherwise exploit your contribution, in source and object form, under any license, including the AGPL-3.0 and the Omnodex commercial license.
3. **You grant Omnodex, and anyone who receives software from Omnodex, a perpetual, worldwide, non-exclusive, royalty-free, irrevocable patent license** to make, have made, use, sell, offer to sell, import, and otherwise transfer your contribution. This license covers only the patent claims you can license that are necessarily infringed by your contribution alone or by its combination with the project it was submitted to. If anyone brings a patent lawsuit alleging that your contribution, or the project it is part of, infringes a patent, the patent license granted to them under this CLA ends on the date that lawsuit is filed.
4. **You retain copyright** to your contribution. This CLA does not transfer ownership - it grants Omnodex the additional rights needed for dual licensing. Omnodex owes you no payment, royalty, or credit for any use of your contribution, including commercial use, beyond the notices the AGPL-3.0 requires in the public distribution.
5. **You understand** that your contribution will be publicly available under the AGPL-3.0, and may also be distributed under the Omnodex commercial license to customers who purchase one.
6. **Third-party material.** If your contribution includes anything you did not write yourself, such as code copied from another project, generated assets, or a new or changed dependency, you will say so in the pull request and give its source and license. You will include it only if its license allows Omnodex to distribute it under both the AGPL-3.0 and the Omnodex commercial license (permissive licenses such as MIT, BSD, or Apache-2.0 usually do), or if you have the owner's written permission. Omnodex may review, reject, or replace any third-party material before merging it or before using it in commercial offerings.
7. **If your employer has rights** to what you create, you have its permission to make the contribution under this CLA, or it has waived those rights.
8. **You warrant** that your contribution does not knowingly infringe any third-party intellectual property rights, and you will tell Omnodex if you learn that any statement in this CLA is no longer accurate.
9. **Omnodex may assign** its rights under this CLA, including to a successor entity.

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
