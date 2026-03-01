# Contributing to @vaultick/crypto

First off, thank you for considering contributing to `@vaultick/crypto`! It's people like you who make it such a great library.

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (Check `.nvmrc` for the recommended version)
- [npm](https://www.npmjs.com/)

### Setup

1.  Fork and clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Ensure everything is working by running tests:
    ```bash
    npm run test:node
    ```

## Development Workflow

1.  **Create a Branch**: Use a descriptive name like `feat/multi-key-support` or `fix/argon2-worker-path`.
2.  **Make Your Changes**: Adhere to the existing coding style (enforced by ESLint and Prettier).
3.  **Add Tests**: Every new feature or bug fix must include corresponding tests in the `tests/` directory.
4.  **Lint & Type-Check**:
    ```bash
    npm run lint
    npm run type-check
    ```
5.  **Verify Coverage**:
    ```bash
    npm run test:node -- --coverage
    ```
6.  **Submit a Pull Request**: Provide a clear description of the changes and link any related issues.

## Style Guidelines

- **TypeScript**: We use strict TypeScript. Avoid using `any` unless absolutely necessary.
- **Documentation**: Use TSDoc for all public-facing APIs.
- **Formatting**: We use Prettier. You can run `npm run format` to format your code.

## Questions?

If you have questions, feel free to open an issue or start a discussion in the repository.
