import { describe, it, expect } from 'vitest';
import * as Errors from '../src/errors';

describe('Errors', () => {
  it('CryptoError should be an instance of Error', () => {
    const error = new Errors.CryptoError('test');
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('CryptoError');
    expect(error.message).toBe('test');
  });

  it('DecryptionError should have a default message', () => {
    const error = new Errors.DecryptionError();
    expect(error).toBeInstanceOf(Errors.CryptoError);
    expect(error.message).toContain('Decryption failed');
  });

  it('InvalidThresholdError should have a default message', () => {
    const error = new Errors.InvalidThresholdError();
    expect(error.message).toContain('Invalid threshold');
  });

  it('InvalidShareCountError should have a default message', () => {
    const error = new Errors.InvalidShareCountError();
    expect(error.message).toContain('Invalid share count');
  });

  it('InsufficientSharesError should format the message correctly', () => {
    const error = new Errors.InsufficientSharesError(1, 2);
    expect(error.message).toContain('unlocked 1/2 required');
  });

  it('ProviderNotFoundError should format the message correctly', () => {
    const error = new Errors.ProviderNotFoundError('Hash', 'Argon2');
    expect(error.message).toContain("Hash provider 'Argon2' not found");
  });

  it('SecureContextError should have a default message', () => {
    const error = new Errors.SecureContextError();
    expect(error.message).toContain('Secure Contexts');
  });

  it('CryptoApiUnavailableError should have a default message', () => {
    const error = new Errors.CryptoApiUnavailableError();
    expect(error.message).toContain('Web Crypto API not available');
  });

  it('InvalidKeyError should have a default message', () => {
    const error = new Errors.InvalidKeyError();
    expect(error.message).toContain('Key must be exactly 256 bits');
  });

  it('UnsupportedVersionError should format the message correctly', () => {
    const error = new Errors.UnsupportedVersionError(2, 1);
    expect(error.message).toContain('Unsupported version: 2. Supported version is 1.');
  });

  it('EmptyDataError should have a default message', () => {
    const error = new Errors.EmptyDataError();
    expect(error.message).toContain('empty data');
  });

  it('EmptyPasswordsError should have a default message', () => {
    const error = new Errors.EmptyPasswordsError();
    expect(error.message).toContain('At least one password');
  });

  it('EmptyKeyError should have a default message', () => {
    const error = new Errors.EmptyKeyError();
    expect(error.message).toContain('Key material cannot be empty');
  });

  it('EmptyIVError should have a default message', () => {
    const error = new Errors.EmptyIVError();
    expect(error.message).toContain('Initialization Vector (IV) cannot be empty');
  });
});
