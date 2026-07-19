import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker, {
  normalizeNewsUrlForDedupe,
  normalizeNewsTitleForDedupe,
  sortYahooCandidates,
  planDailySlotAssignments,
  slotRowToArticle,
  isSlotEligibleCandidate,
  type NewsDailySlotRow,
} from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

type Article = {
  article_id: string;
  title: string;
  description: string;
  image_url: string | null;
  link: string;
  source_id: string;
  pubDate: string;
};

function mkArticle(over: Partial<Article> = {}): Article {
  return {
    article_id: over.article_id ?? 'a1',
    title: over.title ?? 'Title ' + (over.article_id ?? 'a1'),
    description: over.description ?? '',
    image_url: over.image_url ?? null,
    link: over.link ?? `https://news.yahoo.co.jp/pickup/${over.article_id ?? 'a1'}`,
    source_id: over.source_id ?? 'yahoo_news',
    pubDate: over.pubDate ?? '2026-07-19T10:00:00.000Z',
  };
}

function mkSlot(over: Partial<NewsDailySlotRow> = {}): NewsDailySlotRow {
  return {
    category: over.category ?? 'domestic',
    news_date: over.news_date ?? '2026-07-19',
    slot_index: over.slot_index ?? 0,
    source_id: over.source_id ?? 'yahoo_news',
    article_id: over.article_id ?? 's0',
    title: over.title ?? 'Slot ' + (over.slot_index ?? 0),
    description: over.description ?? '',
    image_url: over.image_url ?? null,
    link: over.link ?? `https://news.yahoo.co.jp/pickup/s${over.slot_index ?? 0}`,
    pub_date: over.pub_date ?? '2026-07-19T09:00:00.000Z',
  };
}

// ── URL normalization ──────────────────────────────────────────────
describe('normalizeNewsUrlForDedupe', () => {
  it('removes utm_* parameters', () => {
    const out = normalizeNewsUrlForDedupe('https://a.com/x?utm_source=rss&utm_medium=x&id=5');
    expect(out).not.toMatch(/utm_/);
    expect(out).toContain('id=5');
  });

  it("removes Yahoo's source=rss tracking parameter", () => {
    expect(normalizeNewsUrlForDedupe('https://a.com/x?source=rss')).toBe('https://a.com/x');
  });

  it('removes the fragment', () => {
    expect(normalizeNewsUrlForDedupe('https://a.com/x#frag')).toBe('https://a.com/x');
  });

  it('removes a non-root trailing slash but keeps root', () => {
    expect(normalizeNewsUrlForDedupe('https://a.com/x/')).toBe('https://a.com/x');
    expect(normalizeNewsUrlForDedupe('https://a.com/')).toBe('https://a.com/');
  });

  it('does not throw on an invalid URL', () => {
    expect(() => normalizeNewsUrlForDedupe('not a url')).not.toThrow();
    expect(normalizeNewsUrlForDedupe('not a url')).toBe('not a url');
  });

  it('lowercases the hostname but preserves the path', () => {
    expect(normalizeNewsUrlForDedupe('https://News.Example.COM/Path/Id')).toBe(
      'https://news.example.com/Path/Id'
    );
  });
});

// ── Title normalization ────────────────────────────────────────────
describe('normalizeNewsTitleForDedupe', () => {
  it('applies NFC normalization (decomposed == composed)', () => {
    expect(normalizeNewsTitleForDedupe('\u30cf\u309a')).toBe(normalizeNewsTitleForDedupe('\u30d1'));
  });

  it('collapses repeated whitespace', () => {
    expect(normalizeNewsTitleForDedupe('a   b\t c')).toBe('a b c');
  });

  it('normalizes full-width spaces to normal spaces', () => {
    expect(normalizeNewsTitleForDedupe('東京\u3000地震')).toBe(normalizeNewsTitleForDedupe('東京 地震'));
  });

  it('removes an obvious trailing Yahoo!ニュース suffix', () => {
    const base = normalizeNewsTitleForDedupe('東京で地震');
    expect(normalizeNewsTitleForDedupe('東京で地震 - Yahoo!ニュース')).toBe(base);
    expect(normalizeNewsTitleForDedupe('東京で地震｜Yahoo!ニュース')).toBe(base);
    expect(normalizeNewsTitleForDedupe('東京で地震（Yahoo!ニュース）')).toBe(base);
  });

  it('lowercases Latin text', () => {
    expect(normalizeNewsTitleForDedupe('Hello WORLD')).toBe('hello world');
  });

  it('keeps genuinely different titles different', () => {
    expect(normalizeNewsTitleForDedupe('地震速報 東京')).not.toBe(normalizeNewsTitleForDedupe('地震速報 大阪'));
  });

  it('does not throw on non-string input', () => {
    expect(() => normalizeNewsTitleForDedupe(null as unknown)).not.toThrow();
  });
});

// ── Deterministic ordering ─────────────────────────────────────────
describe('sortYahooCandidates', () => {
  it('orders newer pubDate first', () => {
    const older = mkArticle({ article_id: 'old', pubDate: '2026-07-19T08:00:00.000Z' });
    const newer = mkArticle({ article_id: 'new', pubDate: '2026-07-19T12:00:00.000Z' });
    const out = sortYahooCandidates([older, newer]);
    expect(out.map((a) => a.article_id)).toEqual(['new', 'old']);
  });

  it('breaks equal pubDate ties by article_id ASC', () => {
    const b = mkArticle({ article_id: 'bbb', pubDate: '2026-07-19T10:00:00.000Z' });
    const a = mkArticle({ article_id: 'aaa', pubDate: '2026-07-19T10:00:00.000Z' });
    const out = sortYahooCandidates([b, a]);
    expect(out.map((x) => x.article_id)).toEqual(['aaa', 'bbb']);
  });

  it('does not mutate the input', () => {
    const input = [mkArticle({ article_id: 'x' }), mkArticle({ article_id: 'y' })];
    const snapshot = input.map((a) => a.article_id);
    sortYahooCandidates(input);
    expect(input.map((a) => a.article_id)).toEqual(snapshot);
  });
});

// ── Candidate eligibility ──────────────────────────────────────────
describe('isSlotEligibleCandidate', () => {
  it('accepts a valid article', () => {
    expect(isSlotEligibleCandidate(mkArticle())).toBe(true);
  });
  it('allows a missing image', () => {
    expect(isSlotEligibleCandidate(mkArticle({ image_url: null }))).toBe(true);
  });
  it('rejects a missing title', () => {
    expect(isSlotEligibleCandidate(mkArticle({ title: '' }))).toBe(false);
  });
  it('rejects a missing link', () => {
    expect(isSlotEligibleCandidate(mkArticle({ link: '' }))).toBe(false);
  });
  it('rejects a malformed date', () => {
    expect(isSlotEligibleCandidate(mkArticle({ pubDate: 'not-a-date' }))).toBe(false);
  });
});

// ── Slot assignment ────────────────────────────────────────────────
describe('planDailySlotAssignments', () => {
  it('no existing rows, 5 candidates → indexes 0..4', () => {
    const cands = [0, 1, 2, 3, 4].map((i) =>
      mkArticle({ article_id: `c${i}`, link: `https://x.test/${i}`, title: `t${i}` })
    );
    const out = planDailySlotAssignments([], cands);
    expect(out.map((a) => a.slot_index)).toEqual([0, 1, 2, 3, 4]);
  });

  it('existing 0..4, 3 new candidates → indexes 5,6,7', () => {
    const existing = [0, 1, 2, 3, 4].map((i) => mkSlot({ slot_index: i, article_id: `s${i}`, link: `https://s.test/${i}` }));
    const cands = [0, 1, 2].map((i) =>
      mkArticle({ article_id: `c${i}`, link: `https://x.test/${i}`, title: `t${i}` })
    );
    const out = planDailySlotAssignments(existing, cands);
    expect(out.map((a) => a.slot_index)).toEqual([5, 6, 7]);
  });

  it('sparse existing indexes fill the lowest gaps first', () => {
    const existing = [0, 1, 2, 4].map((i) => mkSlot({ slot_index: i, article_id: `s${i}`, link: `https://s.test/${i}` }));
    const cands = [0, 1, 2, 3].map((i) =>
      mkArticle({ article_id: `c${i}`, link: `https://x.test/${i}`, title: `t${i}` })
    );
    const out = planDailySlotAssignments(existing, cands);
    // empty indexes are 3,5,6,7 in ascending order
    expect(out.map((a) => a.slot_index)).toEqual([3, 5, 6, 7]);
  });

  it('never proposes more than the number of empty slots', () => {
    const existing = [0, 1, 2, 3, 4, 5, 6, 7].map((i) =>
      mkSlot({ slot_index: i, article_id: `s${i}`, link: `https://s.test/${i}` })
    );
    const cands = [0, 1, 2].map((i) => mkArticle({ article_id: `c${i}`, link: `https://x.test/${i}` }));
    expect(planDailySlotAssignments(existing, cands)).toEqual([]);
  });

  it('skips a duplicate (source_id, article_id)', () => {
    const existing = [mkSlot({ slot_index: 0, source_id: 'yahoo_news', article_id: 'dup', link: 'https://s.test/dup' })];
    const cands = [
      mkArticle({ source_id: 'yahoo_news', article_id: 'dup', link: 'https://x.test/other' }),
      mkArticle({ article_id: 'fresh', link: 'https://x.test/fresh' }),
    ];
    const out = planDailySlotAssignments(existing, cands);
    expect(out).toHaveLength(1);
    expect(out[0].article.article_id).toBe('fresh');
  });

  it('skips a normalized-URL duplicate', () => {
    const existing = [mkSlot({ slot_index: 0, article_id: 's0', link: 'https://a.com/story' })];
    const cands = [
      mkArticle({ article_id: 'c1', link: 'https://a.com/story?utm_source=rss#x' }), // same after normalization
      mkArticle({ article_id: 'c2', link: 'https://a.com/other' }),
    ];
    const out = planDailySlotAssignments(existing, cands);
    expect(out.map((a) => a.article.article_id)).toEqual(['c2']);
  });

  it('skips a normalized-title duplicate', () => {
    const existing = [mkSlot({ slot_index: 0, article_id: 's0', title: '東京で地震', link: 'https://s.test/0' })];
    const cands = [
      mkArticle({ article_id: 'c1', title: '東京で地震 - Yahoo!ニュース', link: 'https://x.test/1' }),
      mkArticle({ article_id: 'c2', title: '大阪で大雨', link: 'https://x.test/2' }),
    ];
    const out = planDailySlotAssignments(existing, cands);
    expect(out.map((a) => a.article.article_id)).toEqual(['c2']);
  });

  it('skips candidates duplicated within the same pass', () => {
    const cands = [
      mkArticle({ article_id: 'c1', link: 'https://a.com/s', title: 'same' }),
      mkArticle({ article_id: 'c2', link: 'https://a.com/s?utm_medium=x', title: 'same' }), // dup url+title
      mkArticle({ article_id: 'c3', link: 'https://a.com/diff', title: 'different' }),
    ];
    const out = planDailySlotAssignments([], cands);
    expect(out.map((a) => a.article.article_id)).toEqual(['c1', 'c3']);
    expect(out.map((a) => a.slot_index)).toEqual([0, 1]);
  });

  it('keeps an image-less candidate', () => {
    const out = planDailySlotAssignments([], [mkArticle({ article_id: 'noimg', image_url: null })]);
    expect(out).toHaveLength(1);
  });

  it('skips a malformed candidate (bad date) without consuming a slot', () => {
    const cands = [
      mkArticle({ article_id: 'bad', pubDate: 'nope', link: 'https://x.test/bad' }),
      mkArticle({ article_id: 'good', link: 'https://x.test/good' }),
    ];
    const out = planDailySlotAssignments([], cands);
    expect(out.map((a) => a.article.article_id)).toEqual(['good']);
    expect(out[0].slot_index).toBe(0);
  });
});

// ── Slot row mapping / API compatibility ───────────────────────────
describe('slotRowToArticle', () => {
  it('maps pub_date to pubDate and preserves frontend fields', () => {
    const row = mkSlot({
      article_id: 'z1',
      title: 'T',
      description: 'D',
      image_url: 'https://img.test/a.jpg',
      link: 'https://l.test/a',
      source_id: 'yahoo_news',
      pub_date: '2026-07-19T09:00:00.000Z',
    });
    const a = slotRowToArticle(row);
    expect(a).toEqual({
      article_id: 'z1',
      title: 'T',
      description: 'D',
      image_url: 'https://img.test/a.jpg',
      link: 'https://l.test/a',
      source_id: 'yahoo_news',
      pubDate: '2026-07-19T09:00:00.000Z',
    });
    expect((a as any).slot_index).toBeUndefined();
  });

  it('allows a null image', () => {
    expect(slotRowToArticle(mkSlot({ image_url: null })).image_url).toBeNull();
  });
});

// ── Route behavior (no DB required for these paths) ────────────────
describe('GET /api/rss route', () => {
  it('rejects an invalid category (400) before any work', async () => {
    const request = new IncomingRequest('https://example.com/api/rss?category=nope');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env as any, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
  });

  it('returns empty results for a future date without fetching or writing', async () => {
    const request = new IncomingRequest('https://example.com/api/rss?category=domestic&date=2099-01-01');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env as any, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    const json = (await response.json()) as { status: string; results: unknown[] };
    expect(json.status).toBe('success');
    expect(json.results).toEqual([]);
  });

  it('preserves the response envelope { status, results, request_id }', async () => {
    const request = new IncomingRequest('https://example.com/api/rss?category=domestic&date=2099-01-02');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env as any, ctx);
    await waitOnExecutionContext(ctx);
    const json = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(json).sort()).toEqual(['request_id', 'results', 'status']);
    expect(Array.isArray(json.results)).toBe(true);
    expect((json.results as unknown[]).length).toBeLessThanOrEqual(8);
  });
});
