/**
 * Helper to get the subtle crypto API in both Node and Browser.
 */
function getSubtleCrypto(): SubtleCrypto {
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto.subtle;
  }
  // @ts-ignore
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    // @ts-ignore
    return globalThis.crypto.subtle;
  }
  throw new Error('Web Crypto API not available');
}

/**
 * Generates a random Uint8Array of the given length.
 */
export function generateRandomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(bytes);
  } else {
    // @ts-ignore
    globalThis.crypto.getRandomValues(bytes);
  }
  return bytes;
}

/**
 * Encrypts data using AES-GCM.
 * @param data Data to encrypt.
 * @param key AES key (256-bit).
 * @param iv 12-byte initialization vector.
 * @returns Ciphertext with authentication tag.
 */
export async function encryptAESGCM(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const crypto = getSubtleCrypto();
  const aesKey = await crypto.importKey(
    'raw',
    key as BufferSource,
    'AES-GCM',
    false,
    ['encrypt']
  );

  const encrypted = await crypto.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    aesKey,
    data as BufferSource
  );

  return new Uint8Array(encrypted);
}

/**
 * Decrypts data using AES-GCM.
 * @param ciphertext Data to decrypt.
 * @param key AES key (256-bit).
 * @param iv 12-byte initialization vector.
 * @returns Decrypted data.
 */
export async function decryptAESGCM(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array> {
  const crypto = getSubtleCrypto();
  const aesKey = await crypto.importKey(
    'raw',
    key as BufferSource,
    'AES-GCM',
    false,
    ['decrypt']
  );

  const decrypted = await crypto.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    aesKey,
    ciphertext as BufferSource
  );

  return new Uint8Array(decrypted);
}

/**
 * High-level function to encrypt a file (DEK/KEK pattern).
 * Encrypts data with a randomly generated DEK, then encrypts DEK with KEK.
 */
export async function encryptWithDEK(
  data: Uint8Array,
  kek: Uint8Array
): Promise<{
  ciphertext: Uint8Array;
  wrappedDEK: Uint8Array;
  dataIV: Uint8Array;
  dekIV: Uint8Array;
}> {
  const dek = generateRandomBytes(32); // 256-bit DEK
  const dataIV = generateRandomBytes(12);
  const dekIV = generateRandomBytes(12);

  const ciphertext = await encryptAESGCM(data, dek, dataIV);
  const wrappedDEK = await encryptAESGCM(dek, kek, dekIV);

  return {
    ciphertext,
    wrappedDEK,
    dataIV,
    dekIV,
  };
}

/**
 * High-level function to decrypt a file (DEK/KEK pattern).
 */
export async function decryptWithDEK(
  ciphertext: Uint8Array,
  wrappedDEK: Uint8Array,
  kek: Uint8Array,
  dataIV: Uint8Array,
  dekIV: Uint8Array
): Promise<Uint8Array> {
  const dek = await decryptAESGCM(wrappedDEK, kek, dekIV);
  return await decryptAESGCM(ciphertext, dek, dataIV);
}
