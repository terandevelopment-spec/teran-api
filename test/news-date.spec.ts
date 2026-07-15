import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker, {
  isValidCalendarDate,
  jstDayRangeUtc,
  getJstDateString,
} from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('isValidCalendarDate', () => {
  it('accepts well-formed real calendar dates', () => {
    expect(isValidCalendarDate('2026-07-15')).toBe(true);
    expect(isValidCalendarDate('2024-02-29')).toBe(true); // leap year
    expect(isValidCalendarDate('2000-01-01')).toBe(true);
  });

  it('rejects malformed strings', () => {
    expect(isValidCalendarDate('')).toBe(false);
    expect(isValidCalendarDate('2026-7-5')).toBe(false);
    expect(isValidCalendarDate('2026/07/15')).toBe(false);
    expect(isValidCalendarDate('15-07-2026')).toBe(false);
    expect(isValidCalendarDate('2026-07-15T00:00:00Z')).toBe(false);
    expect(isValidCalendarDate('abcd-ef-gh')).toBe(false);
    // @ts-expect-error runtime guard for non-string input
    expect(isValidCalendarDate(null)).toBe(false);
  });

  it('rejects impossible calendar dates', () => {
    expect(isValidCalendarDate('2026-02-31')).toBe(false);
    expect(isValidCalendarDate('2026-13-01')).toBe(false);
    expect(isValidCalendarDate('2026-00-10')).toBe(false);
    expect(isValidCalendarDate('2026-07-00')).toBe(false);
    expect(isValidCalendarDate('2025-02-29')).toBe(false); // non-leap year
  });
});

describe('jstDayRangeUtc', () => {
  it('maps a JST calendar day to a half-open UTC range (offset -9h)', () => {
    const { startUtc, endUtc } = jstDayRangeUtc('2026-07-15');
    // 2026-07-15T00:00:00+09:00 === 2026-07-14T15:00:00Z
    expect(startUtc).toBe('2026-07-14T15:00:00.000Z');
    // exclusive end is exactly 24h later
    expect(endUtc).toBe('2026-07-15T15:00:00.000Z');
  });

  it('produces a 24h window', () => {
    const { startUtc, endUtc } = jstDayRangeUtc('2026-01-01');
    const ms = new Date(endUtc).getTime() - new Date(startUtc).getTime();
    expect(ms).toBe(24 * 60 * 60 * 1000);
  });
});

describe('getJstDateString', () => {
  it('rolls to the next JST day after 15:00 UTC', () => {
    // 2026-07-14T15:30:00Z === 2026-07-15T00:30:00+09:00
    expect(getJstDateString(new Date('2026-07-14T15:30:00Z'))).toBe('2026-07-15');
  });

  it('stays on the current JST day just before 15:00 UTC', () => {
    // 2026-07-14T14:59:00Z === 2026-07-14T23:59:00+09:00
    expect(getJstDateString(new Date('2026-07-14T14:59:00Z'))).toBe('2026-07-14');
  });

  it('round-trips against jstDayRangeUtc boundaries', () => {
    const { startUtc, endUtc } = jstDayRangeUtc('2026-07-15');
    expect(getJstDateString(new Date(startUtc))).toBe('2026-07-15');
    // one ms before the exclusive end is still the same JST day
    expect(getJstDateString(new Date(new Date(endUtc).getTime() - 1))).toBe('2026-07-15');
    // the exclusive end itself is the next JST day
    expect(getJstDateString(new Date(endUtc))).toBe('2026-07-16');
  });
});

describe('GET /api/rss validation (no external dependencies)', () => {
  it('returns 400 for an invalid category before any fetch/DB work', async () => {
    const request = new IncomingRequest('https://example.com/api/rss?category=nope');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
    const json = (await response.json()) as { status: string; message: string };
    expect(json.status).toBe('error');
    expect(json.message).toContain('Invalid category');
  });

  it('returns 400 for a malformed date parameter', async () => {
    const request = new IncomingRequest('https://example.com/api/rss?category=domestic&date=2026-7-5');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
    const json = (await response.json()) as { status: string; message: string };
    expect(json.status).toBe('error');
    expect(json.message).toContain('YYYY-MM-DD');
  });
});
