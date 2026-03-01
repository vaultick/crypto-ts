import { split, combine } from 'shamir-secret-sharing';
import { SharingProvider, SharingFactory } from './sharing';
import { InvalidThresholdError, InvalidShareCountError, EmptyDataError } from '../errors';

/**
 * An implementation of SharingProvider using Shamir's Secret Sharing scheme.
 * It uses polynomial interpolation to allow secret reconstruction from a subset of shares.
 */
export class ShamirProvider implements SharingProvider {
  /** The unique identifier for this provider. */
  readonly name = 'shamir';

  /**
   * Splits a secret into N shares with a threshold of T.
   *
   * @param secret - The secret material to split.
   * @param n - Total shares to generate.
   * @param t - Minimum shares required for reconstruction.
   * @returns A promise resolving to the generated shares.
   * @throws {EmptyDataError} If the secret is empty.
   * @throws {InvalidShareCountError} If N is less than 1.
   * @throws {InvalidThresholdError} If T is less than 1 or greater than N.
   */
  async split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]> {
    if (secret.length === 0) {
      throw new EmptyDataError('Secret material cannot be empty.');
    }
    if (n < 1) {
      throw new InvalidShareCountError();
    }
    if (t > n || t < 1) {
      throw new InvalidThresholdError();
    }
    return await split(secret, n, t);
  }

  /**
   * Reconstructs the secret from the provided shares.
   * @param shares - An array of shares.
   * @returns A promise resolving to the combined secret.
   */
  async combine(shares: Uint8Array[]): Promise<Uint8Array> {
    return await combine(shares);
  }
}

// Automatically register the provider upon module import.
SharingFactory.addProvider(new ShamirProvider());
