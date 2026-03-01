# @vaultick/crypto

A browser-compatible TypeScript library for advanced cryptographic operations.

## Features

- **AES-GCM Encryption**: Secure file/data encryption using the Web Crypto API.
- **Argon2id Key Derivation**: Derive strong encryption keys from simple passwords using `hash-wasm`.
- **Shamir's Secret Sharing**: Split your encryption keys into $M$-of-$N$ shares for secure storage.
- **DEK/KEK Pattern**: Support for Data Encryption Keys (DEK) wrapped by Key Encryption Keys (KEK).

## Installation

```bash
npm install @vaultick/crypto
```

## Usage

### Password to Key (Argon2id)

```typescript
import { deriveKey, generateRandomBytes } from '@vaultick/crypto';

const password = 'my-secure-password';
const salt = generateRandomBytes(16);
const kek = await deriveKey(password, { salt });
```

### Key Sharing (M-of-N)

```typescript
import { splitKey, combineShares } from '@vaultick/crypto';

const shares = await splitKey(kek, 5, 3); // 5 shares total, 3 required
const recoveredKEK = await combineShares([shares[0], shares[2], shares[4]]);
```

### File Encryption (DEK/KEK)

```typescript
import { encryptWithDEK, decryptWithDEK } from '@vaultick/crypto';

const data = new TextEncoder().encode('Sensitive content');
const { ciphertext, wrappedDEK, dataIV, dekIV } = await encryptWithDEK(data, kek);

// To decrypt:
const decrypted = await decryptWithDEK(
  ciphertext,
  wrappedDEK,
  kek,
  dataIV,
  dekIV
);
```

## Development

- `npm run build`: Build the library.
- `npm run test`: Run tests using Vitest.
- `npm run lint`: Check for type errors.

## License

Apache-2.0
