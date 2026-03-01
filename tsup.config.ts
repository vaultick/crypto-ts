import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/hashing/argon2.worker.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  minify: true,
});
