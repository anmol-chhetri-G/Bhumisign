/**
 * Deterministic JSON (a subset of RFC 8785 / JCS): object keys sorted by UTF-16 code unit,
 * no whitespace, finite safe integers only. Everything we sign is canonicalised first, so
 * the signed bytes never depend on key order or formatting.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value)) {
        throw new Error("canonicalize: only safe integers are allowed");
      }
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
      const record = value as Record<string, unknown>;
      const parts: string[] = [];
      for (const key of Object.keys(record).sort()) {
        const v = record[key];
        if (v === undefined) throw new Error(`canonicalize: undefined value at "${key}"`);
        parts.push(`${JSON.stringify(key)}:${canonicalize(v)}`);
      }
      return `{${parts.join(",")}}`;
    }
    default:
      throw new Error(`canonicalize: unsupported type ${typeof value}`);
  }
}
