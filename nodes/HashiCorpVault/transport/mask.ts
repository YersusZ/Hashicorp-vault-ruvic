const DEFAULT_MASK = '********';
const DEFAULT_PATTERN = '(password|passwd|token|secret|key|credential|private|client_secret|access_key|secret_id|role_id)';

export function defaultMaskPattern(): string {
  return DEFAULT_PATTERN;
}

export function buildMaskRegex(pattern?: string): RegExp {
  const source = pattern && pattern.trim() ? pattern.trim() : DEFAULT_PATTERN;
  try {
    return new RegExp(source, 'i');
  } catch {
    return new RegExp(DEFAULT_PATTERN, 'i');
  }
}

export function maskSecrets(
  value: unknown,
  pattern?: string,
  visited: WeakSet<object> = new WeakSet(),
): unknown {
  const regex = buildMaskRegex(pattern);
  return maskValue(value, regex, visited);
}

function maskValue(value: unknown, regex: RegExp, visited: WeakSet<object>): unknown {
  if (Array.isArray(value)) {
    if (visited.has(value)) {
      return '[Circular]';
    }
    visited.add(value);
    return value.map((item) => maskValue(item, regex, visited));
  }

  if (value && typeof value === 'object') {
    if (visited.has(value)) {
      return '[Circular]';
    }
    visited.add(value);

    const output: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (regex.test(key) && (nested === null || nested === undefined || typeof nested !== 'object')) {
        output[key] = DEFAULT_MASK;
      } else {
        output[key] = maskValue(nested, regex, visited);
      }
    }
    return output;
  }

  return value;
}
