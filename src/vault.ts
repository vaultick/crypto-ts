const MAGIC = new TextEncoder().encode('VLTK'); // Vaultick Magic Bytes
const VERSION = 1;

export interface VaultPackage {
  salt: Uint8Array;
  dataIV: Uint8Array;
  dekIV: Uint8Array;
  wrappedDEK: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Packs cryptographic components into a single binary blob.
 * Format:
 * [4B Magic][1B Version][1B SaltLen][Salt][1B DataIVLen][DataIV][1B DEKIVLen][DEKIV][2B WrappedDEKLen][WrappedDEK][Ciphertext]
 */
export function packVault(pkg: VaultPackage): Uint8Array {
  const totalLength =
    MAGIC.length + // 4
    1 + // version
    1 + pkg.salt.length +
    1 + pkg.dataIV.length +
    1 + pkg.dekIV.length +
    2 + pkg.wrappedDEK.length +
    pkg.ciphertext.length;

  const out = new Uint8Array(totalLength);
  let offset = 0;

  out.set(MAGIC, offset);
  offset += MAGIC.length;

  out[offset++] = VERSION;

  out[offset++] = pkg.salt.length;
  out.set(pkg.salt, offset);
  offset += pkg.salt.length;

  out[offset++] = pkg.dataIV.length;
  out.set(pkg.dataIV, offset);
  offset += pkg.dataIV.length;

  out[offset++] = pkg.dekIV.length;
  out.set(pkg.dekIV, offset);
  offset += pkg.dekIV.length;

  // Use DataView for 16-bit length to avoid endianness issues
  const view = new DataView(out.buffer);
  view.setUint16(offset, pkg.wrappedDEK.length, false); // Big-endian
  offset += 2;
  out.set(pkg.wrappedDEK, offset);
  offset += pkg.wrappedDEK.length;

  out.set(pkg.ciphertext, offset);

  return out;
}

/**
 * Unpacks a binary blob into its cryptographic components.
 */
export function unpackVault(data: Uint8Array): VaultPackage {
  let offset = 0;

  // Check Magic
  for (let i = 0; i < MAGIC.length; i++) {
    if (data[offset++] !== MAGIC[i]) throw new Error('Invalid vault format: magic mismatch');
  }

  const version = data[offset++];
  if (version !== VERSION) throw new Error(`Unsupported vault version: ${version}`);

  const saltLen = data[offset++];
  const salt = data.slice(offset, offset + saltLen);
  offset += saltLen;

  const dataIVLen = data[offset++];
  const dataIV = data.slice(offset, offset + dataIVLen);
  offset += dataIVLen;

  const dekIVLen = data[offset++];
  const dekIV = data.slice(offset, offset + dekIVLen);
  offset += dekIVLen;

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const wrappedDEKLen = view.getUint16(offset, false);
  offset += 2;
  const wrappedDEK = data.slice(offset, offset + wrappedDEKLen);
  offset += wrappedDEKLen;

  const ciphertext = data.slice(offset);

  return { salt, dataIV, dekIV, wrappedDEK, ciphertext };
}
