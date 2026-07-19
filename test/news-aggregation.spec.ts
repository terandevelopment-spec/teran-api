import { describe, it, expect } from 'vitest';
import {
  SECONDARY_NEWS_FEEDS,
  parseNewsRssItems,
  filterCandidatesToJstDay,
  planDailySlotAssignments,
  buildDailySlotRows,
  slotRowToArticle,
  sortYahooCandidates,
  jstDayRangeUtc,
  type NewsDailySlotRow,
} from '../src/index';

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
    link: over.link ?? `https://x.test/${over.article_id ?? 'a1'}`,
    source_id: over.source_id ?? 'nhk',
    pubDate: over.pubDate ?? '2026-07-19T03:00:00.000Z',
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
    link: over.link ?? `https://s.test/${over.slot_index ?? 0}`,
    pub_date: over.pub_date ?? '2026-07-19T02:00:00.000Z',
  };
}

// Simulate the route's two-stage Yahoo→NHK merge without a database: assign
// Yahoo first, fold the accepted assignments into the "canonical" set, then
// assign NHK against that merged set.
function mergeSlots(existing: NewsDailySlotRow[], assigns: Array<{ slot_index: number; article: Article }>): NewsDailySlotRow[] {
  const rows = buildDailySlotRows(assigns as any, 'domestic', '2026-07-19');
  return [...existing, ...rows].sort((a, b) => a.slot_index - b.slot_index);
}

// ── Category configuration ─────────────────────────────────────────
describe('SECONDARY_NEWS_FEEDS category mapping', () => {
  const cases: Array<[string, string]> = [
    ['domestic', 'cat1'],
    ['world', 'cat6'],
    ['business', 'cat5'],
    ['entertainment', 'cat2'],
    ['sports', 'cat7'],
    ['science', 'cat3'],
  ];
  for (const [cat, catN] of cases) {
    it(`${cat} maps to NHK ${catN}`, () => {
      const cfg = SECONDARY_NEWS_FEEDS[cat];
      expect(cfg).toBeDefined();
      expect(cfg.sourceId).toBe('nhk');
      expect(cfg.url).toBe(`https://www.nhk.or.jp/rss/news/${catN}.xml`);
    });
  }

  it('has no secondary feed for it', () => {
    expect(SECONDARY_NEWS_FEEDS['it']).toBeUndefined();
  });
  it('has no secondary feed for local', () => {
    expect(SECONDARY_NEWS_FEEDS['local']).toBeUndefined();
  });
  it('exposes exactly the six supported categories', () => {
    expect(Object.keys(SECONDARY_NEWS_FEEDS).sort()).toEqual(
      ['business', 'domestic', 'entertainment', 'science', 'sports', 'world']
    );
  });
});

// ── NHK RSS parsing ────────────────────────────────────────────────
describe('parseNewsRssItems (NHK)', () => {
  const item = (inner: string) => `<rss><channel>${inner}</channel></rss>`;

  it('parses valid RSS 2.0 with guid isPermaLink, +0900 pubDate, CDATA title', async () => {
    const xml = item(`
      <item>
        <title><![CDATA[東京で地震]]></title>
        <description><![CDATA[詳細です]]></description>
        <link>https://www3.nhk.or.jp/news/html/20260719/k001.html</link>
        <guid isPermaLink="true">https://www3.nhk.or.jp/news/html/20260719/k001.html</guid>
        <pubDate>Sun, 19 Jul 2026 12:00:00 +0900</pubDate>
        <nhknews:new>1</nhknews:new>
      </item>`);
    const out = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(out).toHaveLength(1);
    expect(out[0].source_id).toBe('nhk');
    expect(out[0].title).toBe('東京で地震');
    expect(out[0].description).toBe('詳細です');
    expect(out[0].article_id).toBe('https://www3.nhk.or.jp/news/html/20260719/k001.html');
    expect(out[0].image_url).toBeNull();
    // +0900 12:00 => 03:00Z
    expect(out[0].pubDate).toBe('2026-07-19T03:00:00.000Z');
  });

  it('parses an ordinary (non-CDATA) title', async () => {
    const xml = item(`<item><title>大阪で大雨</title><link>https://n.test/1</link><guid>g1</guid><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    const out = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(out[0].title).toBe('大阪で大雨');
    expect(out[0].article_id).toBe('g1');
  });

  it('derives a deterministic article_id from the link when guid is absent', async () => {
    const xml = item(`<item><title>t</title><link>https://n.test/no-guid</link><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    const a = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    const b = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(a[0].article_id).toBeTruthy();
    expect(a[0].article_id).toBe(b[0].article_id); // deterministic
  });

  it('leaves image_url null when the feed has no image', async () => {
    const xml = item(`<item><title>t</title><link>https://n.test/1</link><guid>g</guid><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    const out = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(out[0].image_url).toBeNull();
  });

  it('accepts an https image enclosure', async () => {
    const xml = item(`<item><title>t</title><link>https://n.test/1</link><guid>g</guid><enclosure url="https://img.test/a.jpg" type="image/jpeg" /><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    const out = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(out[0].image_url).toBe('https://img.test/a.jpg');
  });

  it('skips an item missing a title', async () => {
    const xml = item(`<item><link>https://n.test/1</link><guid>g</guid><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    expect(await parseNewsRssItems(xml, { sourceId: 'nhk' })).toHaveLength(0);
  });

  it('skips an item missing a link', async () => {
    const xml = item(`<item><title>t</title><guid>g</guid><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`);
    expect(await parseNewsRssItems(xml, { sourceId: 'nhk' })).toHaveLength(0);
  });

  it('produces an empty pubDate for an invalid date (later filtered out)', async () => {
    const xml = item(`<item><title>t</title><link>https://n.test/1</link><guid>g</guid><pubDate>not-a-date</pubDate></item>`);
    const out = await parseNewsRssItems(xml, { sourceId: 'nhk' });
    expect(out[0].pubDate).toBe('');
  });

  it('handles malformed XML without throwing', async () => {
    expect(await parseNewsRssItems('<rss><channel><item><title>oops', { sourceId: 'nhk' })).toEqual([]);
  });

  it('respects maxItems', async () => {
    const many = Array.from({ length: 5 }, (_, i) =>
      `<item><title>t${i}</title><link>https://n.test/${i}</link><guid>g${i}</guid><pubDate>Sun, 19 Jul 2026 09:00:00 +0900</pubDate></item>`
    ).join('');
    const out = await parseNewsRssItems(item(many), { sourceId: 'nhk', maxItems: 3 });
    expect(out).toHaveLength(3);
  });
});

// ── JST date filtering ─────────────────────────────────────────────
describe('filterCandidatesToJstDay', () => {
  const { startUtc, endUtc } = jstDayRangeUtc('2026-07-19');
  // start = 2026-07-18T15:00:00Z, end = 2026-07-19T15:00:00Z

  it('accepts an article in the current JST day', () => {
    const a = mkArticle({ pubDate: '2026-07-19T03:00:00.000Z' }); // 12:00 JST
    expect(filterCandidatesToJstDay([a], startUtc, endUtc)).toHaveLength(1);
  });

  it('rejects a previous JST day article', () => {
    const a = mkArticle({ pubDate: '2026-07-18T03:00:00.000Z' }); // 12:00 JST prev day
    expect(filterCandidatesToJstDay([a], startUtc, endUtc)).toHaveLength(0);
  });

  it('rejects a next JST day article', () => {
    const a = mkArticle({ pubDate: '2026-07-19T16:00:00.000Z' }); // 01:00 JST next day
    expect(filterCandidatesToJstDay([a], startUtc, endUtc)).toHaveLength(0);
  });

  it('accepts the exact lower boundary', () => {
    const a = mkArticle({ pubDate: startUtc });
    expect(filterCandidatesToJstDay([a], startUtc, endUtc)).toHaveLength(1);
  });

  it('rejects the exact upper boundary (half-open)', () => {
    const a = mkArticle({ pubDate: endUtc });
    expect(filterCandidatesToJstDay([a], startUtc, endUtc)).toHaveLength(0);
  });

  it('rejects an invalid/empty pubDate', () => {
    expect(filterCandidatesToJstDay([mkArticle({ pubDate: '' })], startUtc, endUtc)).toHaveLength(0);
    expect(filterCandidatesToJstDay([mkArticle({ pubDate: 'nope' })], startUtc, endUtc)).toHaveLength(0);
  });
});

// ── Source priority (existing → Yahoo → NHK) ───────────────────────
describe('source priority and NHK slot filling', () => {
  it('Yahoo receives lower empty indexes before NHK, NHK fills the rest', () => {
    const existing = [0, 1, 2].map((i) => mkSlot({ slot_index: i, article_id: `s${i}`, link: `https://s.test/${i}` }));
    const yahoo = [0, 1].map((i) =>
      mkArticle({ source_id: 'yahoo_news', article_id: `y${i}`, link: `https://y.test/${i}`, title: `y${i}` })
    );
    const nhk = [0, 1, 2].map((i) =>
      mkArticle({ source_id: 'nhk', article_id: `n${i}`, link: `https://n.test/${i}`, title: `n${i}` })
    );

    const yAssign = planDailySlotAssignments(existing, sortYahooCandidates(yahoo));
    expect(yAssign.map((a) => a.slot_index)).toEqual([3, 4]);

    const merged = mergeSlots(existing, yAssign as any);
    const nAssign = planDailySlotAssignments(merged, sortYahooCandidates(nhk));
    expect(nAssign.map((a) => a.slot_index)).toEqual([5, 6, 7]);
    // NHK never took a Yahoo index (3,4)
    expect(nAssign.every((a) => a.slot_index >= 5)).toBe(true);
    expect(nAssign.every((a) => a.article.source_id === 'nhk')).toBe(true);
  });

  it('0 existing, Yahoo 5 + NHK 3 → final 8', () => {
    const yahoo = [0, 1, 2, 3, 4].map((i) => mkArticle({ source_id: 'yahoo_news', article_id: `y${i}`, link: `https://y.test/${i}`, title: `y${i}` }));
    const nhk = [0, 1, 2, 3].map((i) => mkArticle({ source_id: 'nhk', article_id: `n${i}`, link: `https://n.test/${i}`, title: `n${i}` }));
    const yAssign = planDailySlotAssignments([], sortYahooCandidates(yahoo));
    expect(yAssign.map((a) => a.slot_index)).toEqual([0, 1, 2, 3, 4]);
    const merged = mergeSlots([], yAssign as any);
    const nAssign = planDailySlotAssignments(merged, sortYahooCandidates(nhk));
    expect(nAssign.map((a) => a.slot_index)).toEqual([5, 6, 7]); // only 3 empty remain
    expect(merged.length + nAssign.length).toBe(8);
  });

  it('when Yahoo fills all remaining slots there is nothing left for NHK', () => {
    const existing = [0, 1, 2, 3, 4].map((i) => mkSlot({ slot_index: i, article_id: `s${i}`, link: `https://s.test/${i}` }));
    const yahoo = [0, 1, 2].map((i) => mkArticle({ source_id: 'yahoo_news', article_id: `y${i}`, link: `https://y.test/${i}` }));
    const yAssign = planDailySlotAssignments(existing, sortYahooCandidates(yahoo));
    const merged = mergeSlots(existing, yAssign as any);
    expect(merged.length).toBe(8);
    const nAssign = planDailySlotAssignments(merged, sortYahooCandidates([mkArticle({ article_id: 'n0' })]));
    expect(nAssign).toEqual([]);
  });
});

// ── Deduplication (NHK vs existing / Yahoo / within-NHK) ───────────
describe('NHK deduplication', () => {
  it('skips NHK when normalized URL matches a Yahoo slot', () => {
    const existing = [mkSlot({ slot_index: 0, source_id: 'yahoo_news', article_id: 'y0', link: 'https://a.com/story' })];
    const nhk = [
      mkArticle({ source_id: 'nhk', article_id: 'n0', link: 'https://a.com/story?utm_source=rss#x' }),
      mkArticle({ source_id: 'nhk', article_id: 'n1', link: 'https://a.com/other' }),
    ];
    const out = planDailySlotAssignments(existing, sortYahooCandidates(nhk));
    expect(out.map((a) => a.article.article_id)).toEqual(['n1']);
  });

  it('skips NHK when normalized title matches (NHK suffix ignored)', () => {
    const existing = [mkSlot({ slot_index: 0, source_id: 'yahoo_news', article_id: 'y0', title: '東京で地震', link: 'https://s.test/0' })];
    const nhk = [
      mkArticle({ source_id: 'nhk', article_id: 'n0', title: '東京で地震（NHK）', link: 'https://n.test/0' }),
      mkArticle({ source_id: 'nhk', article_id: 'n1', title: '別の見出し', link: 'https://n.test/1' }),
    ];
    const out = planDailySlotAssignments(existing, sortYahooCandidates(nhk));
    expect(out.map((a) => a.article.article_id)).toEqual(['n1']);
  });

  it('retains the same broad event when titles differ (no fuzzy matching)', () => {
    const existing = [mkSlot({ slot_index: 0, title: '首相が会見', link: 'https://s.test/0' })];
    const nhk = [mkArticle({ source_id: 'nhk', article_id: 'n0', title: '総理大臣が記者会見で発言', link: 'https://n.test/0' })];
    const out = planDailySlotAssignments(existing, sortYahooCandidates(nhk));
    expect(out).toHaveLength(1);
  });

  it('skips a duplicate within the NHK feed', () => {
    const nhk = [
      mkArticle({ source_id: 'nhk', article_id: 'n0', link: 'https://a.com/s', title: 'same' }),
      mkArticle({ source_id: 'nhk', article_id: 'n1', link: 'https://a.com/s?utm_medium=x', title: 'same' }),
      mkArticle({ source_id: 'nhk', article_id: 'n2', link: 'https://a.com/diff', title: 'diff' }),
    ];
    const out = planDailySlotAssignments([], sortYahooCandidates(nhk));
    expect(out.map((a) => a.article.article_id)).toEqual(['n0', 'n2']);
  });

  it('skips a source/article-id duplicate', () => {
    const existing = [mkSlot({ slot_index: 0, source_id: 'nhk', article_id: 'dup', link: 'https://s.test/0' })];
    const nhk = [
      mkArticle({ source_id: 'nhk', article_id: 'dup', link: 'https://n.test/other' }),
      mkArticle({ source_id: 'nhk', article_id: 'fresh', link: 'https://n.test/fresh' }),
    ];
    const out = planDailySlotAssignments(existing, sortYahooCandidates(nhk));
    expect(out.map((a) => a.article.article_id)).toEqual(['fresh']);
  });
});

// ── Persistence & API compatibility ────────────────────────────────
describe('NHK slot persistence and API compatibility', () => {
  it('builds a full snapshot row with source_id "nhk" and null image', () => {
    const assigns = [{ slot_index: 5, article: mkArticle({ source_id: 'nhk', article_id: 'n0', title: 'T', description: 'D', image_url: null, link: 'https://n.test/0', pubDate: '2026-07-19T03:00:00.000Z' }) }];
    const rows = buildDailySlotRows(assigns as any, 'domestic', '2026-07-19');
    expect(rows[0]).toEqual({
      category: 'domestic',
      news_date: '2026-07-19',
      slot_index: 5,
      source_id: 'nhk',
      article_id: 'n0',
      title: 'T',
      description: 'D',
      image_url: null,
      link: 'https://n.test/0',
      pub_date: '2026-07-19T03:00:00.000Z',
      selected_at: expect.any(String),
    });
  });

  it('maps an NHK slot back to the frontend shape (pubDate, no slot_index)', () => {
    const row = mkSlot({ source_id: 'nhk', article_id: 'n0', pub_date: '2026-07-19T03:00:00.000Z' });
    const a = slotRowToArticle(row);
    expect(a.source_id).toBe('nhk');
    expect(a.pubDate).toBe('2026-07-19T03:00:00.000Z');
    expect((a as any).slot_index).toBeUndefined();
    expect((a as any).pub_date).toBeUndefined();
  });
});
