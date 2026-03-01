import { describe, it, expect } from 'vitest';
import { packVault, unpackVault, VaultPackage, generateRandomBytes } from '../src';

describe('Vault Packing Format', () => {
  it('should correctly pack and unpack a VaultPackage', () => {
    const pkg: VaultPackage = {
      salt: generateRandomBytes(16),
      dataIV: generateRandomBytes(12),
      dekIV: generateRandomBytes(12),
      wrappedDEK: generateRandomBytes(48), // 32 + 16 (tag)
      ciphertext: new TextEncoder().encode('This is the secret content'),
    };

    const packed = packVault(pkg);
    const unpacked = unpackVault(packed);

    expect(unpacked.salt).toEqual(pkg.salt);
    expect(unpacked.dataIV).toEqual(pkg.dataIV);
    expect(unpacked.dekIV).toEqual(pkg.dekIV);
    expect(unpacked.wrappedDEK).toEqual(pkg.wrappedDEK);
    expect(unpacked.ciphertext).toEqual(pkg.ciphertext);
  });

  it('should throw error on invalid magic', () => {
    const invalid = new Uint8Array([1, 2, 3, 4, 1, 16, 0]);
    expect(() => unpackVault(invalid)).toThrow('Invalid vault format: magic mismatch');
  });

  it('should throw error on unsupported version', () => {
    const pkg: VaultPackage = {
      salt: generateRandomBytes(1),
      dataIV: generateRandomBytes(1),
      dekIV: generateRandomBytes(1),
      wrappedDEK: generateRandomBytes(1),
      ciphertext: new Uint8Array([0]),
    };
    const packed = packVault(pkg);
    packed[4] = 99; // Set version to 99
    expect(() => unpackVault(packed)).toThrow('Unsupported vault version: 99');
  });
});
