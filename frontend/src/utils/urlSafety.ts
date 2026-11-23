/**
 * Sanitize an untrusted URL for safe use in navigation (`window.open`),
 * `<a href>`, `<img src>`, `<video src>`, and favicon `<link href>`.
 *
 * Accepts only explicit `http://` / `https://` URLs or (when `allowRelative` is
 * true) single-slash same-origin relative paths (`/path`, rejecting `//host` and
 * `/\host`). Returns `null` for `javascript:`, `data:`, `vbscript:`, `file:`,
 * control-character obfuscated schemes, or malformed inputs.
 */
export function sanitizeSafeUrl(
  rawUrl?: string | null,
  allowRelative = true
): string | null {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;

  // Reject ASCII control characters commonly used to bypass naive scheme checks.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(trimmed)) {
    return null;
  }

  if (allowRelative && trimmed.startsWith('/')) {
    if (trimmed.startsWith('//') || trimmed.startsWith('/\\')) {
      return null;
    }
    try {
      const parsed = new URL(trimmed, 'https://localhost.invalid');
      if (parsed.origin !== 'https://localhost.invalid') {
        return null;
      }
      return trimmed;
    } catch {
      return null;
    }
  }

  if (!/^https?:\/\//i.test(trimmed)) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}
