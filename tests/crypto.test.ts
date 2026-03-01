import { describe, it, expect } from 'vitest';
import { deriveKey, splitKey, combineShares, encryptWithDEK, decryptWithDEK, generateRandomBytes } from '../src';

describe('ts-crypto library', () => {
  it('should derive a key from a password', async () => {
    const password = 'my-secure-password';
    const salt = generateRandomBytes(16);
    const key = await deriveKey(password, { salt });
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('should split and combine a key (M-of-N)', async () => {
    const secret = generateRandomBytes(32);
    const n = 5;
    const t = 3;

    const shares = await splitKey(secret, n, t);
    expect(shares.length).toBe(n);

    // Reconstruct with threshold
    const recovered = await combineShares([shares[0], shares[2], shares[4]]);
    expect(recovered).toEqual(secret);
  });

  it('should encrypt and decrypt using DEK/KEK pattern', async () => {
    const kek = generateRandomBytes(32);
    const data = new TextEncoder().encode('Hello World, this is a secret message.');

    const result = await encryptWithDEK(data, kek);

    const decrypted = await decryptWithDEK(
      result.ciphertext,
      result.wrappedDEK,
      kek,
      result.dataIV,
      result.dekIV
    );

    expect(new TextDecoder().decode(decrypted)).toBe('Hello World, this is a secret message.');
  });

  it('should work together: Password -> KEK -> Shares -> DEK', async () => {
    // 1. Password to KEK
    const password = 'super-secret-password';
    const salt = generateRandomBytes(16);
    const kek = await deriveKey(password, { salt });

    // 2. Encrypt data with DEK, DEK wrapped by KEK
    const data = new TextEncoder().encode('Ultimate Secret Data');
    const { ciphertext, wrappedDEK, dataIV, dekIV } = await encryptWithDEK(data, kek);

    // 3. Split KEK into 2-of-3 shares
    const kekShares = await splitKey(kek, 3, 2);

    // --- Recovery ---
    
    // 4. Combine shares to get KEK
    const recoveredKEK = await combineShares([kekShares[1], kekShares[2]]);
    expect(recoveredKEK).toEqual(kek);

    // 5. Decrypt using recovered KEK
    const recoveredData = await decryptWithDEK(
      ciphertext,
      wrappedDEK,
      recoveredKEK,
      dataIV,
      dekIV
    );

    expect(new TextDecoder().decode(recoveredData)).toBe('Ultimate Secret Data');
  });
});
