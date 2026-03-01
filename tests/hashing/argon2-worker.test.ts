import { describe, it, expect } from 'vitest';
import { Argon2WorkerProvider } from '../../src/hashing/argon2-worker-provider';
import { NativeProvider } from '../../src/randomness/native';

describe('Argon2WorkerProvider', () => {
  // We only run this in the browser because creating Web Workers from TS files 
  // is natively supported in many modern build tools/environments that Vitest Browser emulates.
  // In Node.js, this would require a different setup.
  
  it('should derive a key using a worker', { skip: typeof window === 'undefined' }, async () => {
    const workerFactory = () => new Worker(new URL('../../src/hashing/argon2.worker.ts', import.meta.url), { type: 'module' });
    
    // Use lower parameters for faster tests
    const options = {
      iterations: 1,
      memorySize: 1024,
      parallelism: 1,
      hashLength: 32
    };
    
    const provider = new Argon2WorkerProvider(workerFactory, options);
    const randomness = new NativeProvider();
    const password = 'worker-password';
    const salt = randomness.generate(16);

    const key = await provider.derive(password, salt);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
    
    expect(provider.getParams().iterations).toBe(options.iterations);
    
    provider.terminate();
  });

  it('should handle worker errors', { skip: typeof window === 'undefined' }, async () => {
    // Mock worker that returns an error
    const mockWorker = {
      postMessage: function(data: any) {
        setTimeout(() => {
          if (this.onmessage) {
            this.onmessage({
              data: {
                id: data.id,
                error: 'Mock Worker Error'
              }
            } as MessageEvent);
          }
        }, 10);
      },
      terminate: () => {},
      onmessage: null as ((e: MessageEvent) => void) | null
    };
    
    const workerFactory = () => mockWorker as unknown as Worker;
    const provider = new Argon2WorkerProvider(workerFactory);
    const randomness = new NativeProvider();
    const salt = randomness.generate(16);

    await expect(provider.derive('password', salt)).rejects.toThrow('Mock Worker Error');
  });
});
