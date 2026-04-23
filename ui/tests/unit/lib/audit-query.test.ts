import { describe, it, expect } from 'vitest';
import { buildAuditQueryString } from '../../../src/lib/api';

describe('buildAuditQueryString', () => {
  it('returns an empty query string when no params are set', () => {
    expect(buildAuditQueryString({}).toString()).toBe('');
  });

  it('serializes pagination params', () => {
    const qs = buildAuditQueryString({ limit: 50, offset: 100 });
    expect(qs.get('limit')).toBe('50');
    expect(qs.get('offset')).toBe('100');
  });

  it('joins event_type list with commas', () => {
    const qs = buildAuditQueryString({ event_type: ['login_success', 'login_failed'] });
    expect(qs.get('event_type')).toBe('login_success,login_failed');
  });

  it('omits empty event_type arrays', () => {
    const qs = buildAuditQueryString({ event_type: [] });
    expect(qs.has('event_type')).toBe(false);
  });

  it('serializes time range as unix seconds', () => {
    const qs = buildAuditQueryString({ since: 1700000000, until: 1710000000 });
    expect(qs.get('since')).toBe('1700000000');
    expect(qs.get('until')).toBe('1710000000');
  });

  it('includes zero-valued pagination params (offset=0 is significant)', () => {
    const qs = buildAuditQueryString({ offset: 0, limit: 50 });
    expect(qs.get('offset')).toBe('0');
  });

  it('drops blank string IDs', () => {
    // Caller is expected to trim and drop empties; we only skip falsy values.
    const qs = buildAuditQueryString({ user_id: '', actor_id: '' });
    expect(qs.has('user_id')).toBe(false);
    expect(qs.has('actor_id')).toBe(false);
  });

  it('includes string IDs when present', () => {
    const qs = buildAuditQueryString({
      user_id: '00000000-0000-0000-0000-000000000001',
      actor_id: '00000000-0000-0000-0000-000000000002',
    });
    expect(qs.get('user_id')).toBe('00000000-0000-0000-0000-000000000001');
    expect(qs.get('actor_id')).toBe('00000000-0000-0000-0000-000000000002');
  });
});
