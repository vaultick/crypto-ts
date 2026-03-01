import { EncodingProvider, EncodingFactory } from './encoding';

export class Base64Engine implements EncodingProvider {
  readonly name = 'base64';
  btoa(str: string): string {
    if (typeof window !== 'undefined' && window.btoa) return window.btoa(str);
    return Buffer.from(str, 'binary').toString('base64');
  }

  atob(b64: string): string {
    if (typeof window !== 'undefined' && window.atob) return window.atob(b64);
    return Buffer.from(b64, 'base64').toString('binary');
  }
}

EncodingFactory.addProvider(new Base64Engine());
