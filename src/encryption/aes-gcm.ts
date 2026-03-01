import { EncryptionProvider, EncryptionFactory } from './encryption';

export class AESGCMProvider implements EncryptionProvider {
  readonly name = 'aes-gcm';
  private getSubtleCrypto(): SubtleCrypto {
    if (typeof globalThis !== 'undefined' && 'isSecureContext' in globalThis && !globalThis.isSecureContext) {
      throw new Error('Web Crypto API is only available in Secure Contexts (HTTPS or localhost).');
    }

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

  async encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    const crypto = this.getSubtleCrypto();
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

  async decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    const crypto = this.getSubtleCrypto();
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
}

EncryptionFactory.addProvider(new AESGCMProvider());
