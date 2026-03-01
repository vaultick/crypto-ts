import { EncodingProvider, EncodingFactory } from './encoding';

/**
 * An implementation of EncodingProvider using the Base64 scheme.
 * Provides environment-aware transformation between strings and Base64.
 */
export class Base64Engine implements EncodingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'base64';

  /**
   * Encodes a string into its Base64 representation.
   * @param str - The raw string.
   * @returns The Base64 encoded string.
   */
  btoa(str: string): string {
    if (typeof window !== 'undefined' && window.btoa) return window.btoa(str);
    return Buffer.from(str, 'binary').toString('base64');
  }

  /**
   * Decodes a Base64 encoded string.
   * @param b64 - The Base64 string.
   * @returns The decoded original string.
   */
  atob(b64: string): string {
    if (typeof window !== 'undefined' && window.atob) return window.atob(b64);
    return Buffer.from(b64, 'base64').toString('binary');
  }
}

// Automatically register the provider upon module import.
EncodingFactory.addProvider(new Base64Engine());
