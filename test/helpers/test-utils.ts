export function headersToRecord(headers: Headers): Record<string, string> {
  return Object.fromEntries(Array.from(headers.entries()));
}

export class FakeRedis {
  private readonly hashes = new Map<string, Map<string, string>>();
  private readonly kv = new Map<string, { value: string; expiresAt: number | null }>();

  async hGet(key: string, field: string): Promise<string | null> {
    return this.hashes.get(key)?.get(field) ?? null;
  }

  async hSet(key: string, field: string, value: string): Promise<number> {
    const hash = this.hashes.get(key) ?? new Map<string, string>();
    this.hashes.set(key, hash);
    hash.set(field, value);
    return 1;
  }

  async hDel(key: string, field: string): Promise<number> {
    const hash = this.hashes.get(key);
    if (!hash) {
      return 0;
    }
    const existed = hash.delete(field);
    return existed ? 1 : 0;
  }

  async hKeys(key: string): Promise<string[]> {
    return Array.from(this.hashes.get(key)?.keys() ?? []);
  }

  async set(key: string, value: string, ...args: unknown[]): Promise<"OK" | null> {
    this.cleanup();

    let nx = false;
    let exSeconds: number | null = null;

    if (args.length === 1 && typeof args[0] === "object" && args[0] != null) {
      const options = args[0] as { NX?: boolean; EX?: number };
      nx = options.NX === true;
      exSeconds = typeof options.EX === "number" ? options.EX : null;
    } else {
      for (let i = 0; i < args.length; i += 1) {
        const token = String(args[i] ?? "").toUpperCase();
        if (token === "NX") {
          nx = true;
          continue;
        }
        if (token === "EX") {
          const raw = args[i + 1];
          exSeconds = Number(raw);
          i += 1;
        }
      }
    }

    if (nx && this.kv.has(key)) {
      return null;
    }

    const expiresAt = exSeconds == null ? null : Date.now() + exSeconds * 1000;
    this.kv.set(key, { value, expiresAt });
    return "OK";
  }

  async get(key: string): Promise<string | null> {
    this.cleanup();
    const entry = this.kv.get(key);
    return entry ? entry.value : null;
  }

  async del(key: string | string[]): Promise<number> {
    const keys = Array.isArray(key) ? key : [key];
    let removed = 0;
    for (const k of keys) {
      if (this.kv.delete(k)) {
        removed += 1;
      }
      if (this.hashes.delete(k)) {
        removed += 1;
      }
    }
    return removed;
  }

  hasHashKey(key: string): boolean {
    return this.hashes.has(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.kv.entries()) {
      if (entry.expiresAt != null && entry.expiresAt <= now) {
        this.kv.delete(key);
      }
    }
  }
}
