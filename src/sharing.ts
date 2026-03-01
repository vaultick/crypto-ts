import { split, combine } from 'shamir-secret-sharing';

/**
 * Splits a secret (e.g., an encryption key) into n shares, requiring t to reconstruct.
 * @param secret The secret to split.
 * @param n Total number of shares to generate.
 * @param t Threshold (minimum number of shares required to reconstruct).
 * @returns Array of shares as Uint8Arrays.
 */
export async function splitKey(
  secret: Uint8Array,
  n: number,
  t: number
): Promise<Uint8Array[]> {
  if (t > n) {
    throw new Error('Threshold cannot be greater than the number of shares');
  }
  return await split(secret, n, t);
}

/**
 * Reconstructs the original secret from at least t shares.
 * @param shares Array of shares.
 * @returns The reconstructed secret.
 */
export async function combineShares(shares: Uint8Array[]): Promise<Uint8Array> {
  return await combine(shares);
}
