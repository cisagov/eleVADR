export function getNestedValue(row: unknown, key: string): unknown {
  if (!row || typeof row !== "object") {
    return undefined;
  }

  const rowObject = row as Record<string, unknown>;

  if (key in rowObject) {
    return rowObject[key];
  }

  return key.split(".").reduce<unknown>((current, part) => {
    if (current && typeof current === "object") {
      return (current as Record<string, unknown>)[part];
    }
    return undefined;
  }, row);
}

export function toFilterableString(value: unknown): string {
  if (value == null) {
    return "";
  }

  if (Array.isArray(value)) {
    return value.map(toFilterableString).join(" ");
  }

  if (typeof value === "object") {
    return Object.values(value as Record<string, unknown>)
      .map(toFilterableString)
      .join(" ");
  }

  return String(value);
}
