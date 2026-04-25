import { Injectable, signal, Signal, WritableSignal } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class CacheService {
  private store = new Map<string, WritableSignal<unknown>>();

  private getOrCreate<T>(key: string): WritableSignal<T | null> {
    if (!this.store.has(key)) {
      this.store.set(key, signal<T | null>(null));
    }
    return this.store.get(key) as WritableSignal<T | null>;
  }

  set<T>(key: string, data: T): void {
    this.getOrCreate<T>(key).set(data);
  }

  get<T>(key: string): T | null {
    return (this.store.get(key)?.() as T | null) ?? null;
  }

  // Devuelve una Signal reactiva: cuando se llame a set(), la vista se actualiza sola
  signal<T>(key: string): Signal<T | null> {
    return this.getOrCreate<T>(key).asReadonly();
  }

  invalidate(key: string): void {
    this.store.get(key)?.set(null);
  }

  invalidateAll(): void {
    this.store.forEach(s => s.set(null));
  }
}
