import { Factory, NamedProvider } from '../factory';

/**
 * Interface for encoding engines.
 * Providers are responsible for transforming binary data to string representations and vice versa.
 */
export interface EncodingProvider extends NamedProvider {
  /**
   * Encodes binary data into a string.
   * @param str - The string to encode (e.g., a JSON string).
   * @returns The encoded string.
   */
  btoa(str: string): string;

  /**
   * Decodes an encoded string back to its original representation.
   * @param b64 - The encoded string (e.g., Base64).
   * @returns The decoded string.
   */
  atob(b64: string): string;
}

/**
 * Global factory for managing encoding providers.
 */
export const EncodingFactory = new Factory<EncodingProvider>('Encoding');
