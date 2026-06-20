// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import DOMPurify from 'dompurify';

// Prosta implementacja esc dla testów
const esc = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

describe('XSS prevention', () => {
  it('esc() escapes HTML special chars', () => {
    expect(esc('<script>alert(1)</script>')).not.toContain('<script>');
    expect(esc('"quoted"')).toBe('&quot;quoted&quot;');
  });

  it('DOMPurify blocks script injection', () => {
    const malicious = '<strong>ok</strong><script>alert(1)</script>';
    const sanitized = DOMPurify.sanitize(malicious, { ALLOWED_TAGS: ['strong', 'em', 'code'] });
    expect(sanitized).not.toContain('<script>');
    expect(sanitized).toContain('<strong>ok</strong>');
  });
});
