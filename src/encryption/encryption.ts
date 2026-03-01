import { Factory, NamedProvider } from '../factory';

/**
 * Interface for encryption engines.
 * Providers must implement secure symmetric encryption and decryption.
 */
export interface EncryptionProvider extends NamedProvider {
  /**
   * Encrypts the provided data using a symmetric key and initialization vector.
   *
   * @param data - The raw data to encrypt.
   * @param key - The symmetric key material (e.g., 32 bytes for AES-256).
   * @param iv - The initialization vector (e.g., 12 bytes for AES-GCM).
   * @returns A promise that resolves to the encrypted ciphertext.
   */
  encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;

  /**
   * Decrypts the provided ciphertext using a symmetric key and initialization vector.
   *
   * @param ciphertext - The encrypted data to decrypt.
   * @param key - The symmetric key material used for encryption.
   * @param iv - The initialization vector used for encryption.
   * @returns A promise that resolves to the original plaintext data.
   */
  decrypt(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
}

/**
 * Global factory for managing encryption providers.
 */
export const EncryptionFactory = new Factory<EncryptionProvider>('Encryption');
