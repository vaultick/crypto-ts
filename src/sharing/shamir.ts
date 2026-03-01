import { split, combine } from 'shamir-secret-sharing';
import { SharingProvider, SharingFactory } from './sharing';

export class ShamirProvider implements SharingProvider {
  readonly name = 'shamir';
  async split(secret: Uint8Array, n: number, t: number): Promise<Uint8Array[]> {
    if (t > n) {
      throw new Error('Threshold cannot be greater than the number of shares');
    }
    return await split(secret, n, t);
  }

  async combine(shares: Uint8Array[]): Promise<Uint8Array> {
    return await combine(shares);
  }
}

SharingFactory.addProvider(new ShamirProvider());
