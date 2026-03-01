/**
 * Base interface for all providers that can be registered in a Factory.
 */
export interface NamedProvider {
  /** The unique identifier for this provider implementation. */
  name: string;
}

/**
 * A generic factory for managing and retrieving named provider implementations.
 * @template T - A provider type that extends NamedProvider.
 */
export class Factory<T extends NamedProvider> {
  /**
   * @param type - A descriptive name for the type of providers managed by this factory (used for error messages).
   */
  constructor(private readonly type: string) {}

  private providers = new Map<string, T>();

  /**
   * Registers a new provider implementation.
   * @param provider - The provider instance to add.
   */
  addProvider(provider: T): void {
    this.providers.set(provider.name, provider);
  }

  /**
   * Retrieves a registered provider by its name.
   * @param name - The name of the provider to retrieve.
   * @returns The requested provider instance.
   * @throws {ProviderNotFoundError} If no provider with the given name is registered.
   */
  getProvider(name: string): T {
    const provider = this.providers.get(name);

    if (!provider) {
      throw new ProviderNotFoundError(this.type, name);
    }

    return provider;
  }
}

import { ProviderNotFoundError } from './errors';
