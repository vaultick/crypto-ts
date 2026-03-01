# @vaultick/crypto

A browser-compatible TypeScript library for advanced cryptographic operations.

## Features

- **Key & Document Architecture**: Industrial-grade separation of credentials, key management, and data storage.
- **M-of-N Key Protection**: Split your Master Key into shares protected by multiple passwords.
- **Generic Hashing**: Pluggable hashing providers (Argon2id by default).
- **Exportable Blobs**: Keys and Documents are easily exportable to Base64 for API use.
- **AES-GCM Encryption**: Secure data encryption using the Web Crypto API.

## Installation

```bash
npm install @vaultick/crypto
```

## Usage

### 1. The Key (In-Memory Only)

A `Key` represents a derived secret. It should never be persisted directly.

```typescript
import { Key, Argon2Provider, generateRandomBytes } from '@vaultick/crypto';

// Generate a new random master key
const key = Key.generate();
```

### 2. Encrypting the Key (For Persistence)

You "encrypt" a `Key` with one or more passwords to persist it safely.

#### Single Password Protection
```typescript
const encryptedKey = await key.encrypt(['my-password'], 1);
const keyBlob = encryptedKey.encode(); // Save this Base64 string
```

#### M-of-N Protection (e.g., 2-of-3)
```typescript
const encryptedKey = await key.encrypt(['p1', 'p2', 'p3'], 2);
```

### 3. The Document (Data Storage)

A `Document` contains your encrypted data. It uses an unlocked `Key` to perform the encryption.

```typescript
import { Document } from '@vaultick/crypto';

const data = new TextEncoder().encode('My secret file content');
const document = await Document.encrypt(data, key);
const documentBlob = document.encode(); // Save this Base64 string
```

### 4. Recovery (Decryption)

```typescript
import { Key, EncryptedKey, Document } from '@vaultick/crypto';

// 1. Import and decrypt the Key
const ek = EncryptedKey.decode(storedKeyBlob);
const key = await ek.decrypt(['my-password']);

// 2. Import and decrypt the Document
const document = Document.decode(storedDocumentBlob);
const decrypted = await document.decrypt(key);
```

## Development

- `npm run build`: Build the library.
- `npm run test`: Run tests using Vitest.
- `npm run lint`: Check for type errors.

## License

Apache-2.0
