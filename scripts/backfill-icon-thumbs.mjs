#!/usr/bin/env node
/**
 * backfill-icon-thumbs.mjs
 *
 * One-time backfill: generate icon_thumb_key for rooms that have icon_key but
 * no icon_thumb_key. Safe to stop and rerun — already-populated rows are skipped.
 *
 * Prerequisites:
 *   npm install -D sharp            (image resize)
 *   Apply sql/room_icon_thumb.sql   (adds icon_thumb_key column)
 *   Deploy API with icon_thumb_key support
 *
 * Required env (add to .dev.vars or export before running):
 *   SUPABASE_URL               – Supabase project URL
 *   SUPABASE_SERVICE_ROLE_KEY  – Supabase service-role key (full DB access)
 *   CF_ACCOUNT_ID              – Cloudflare account ID
 *   R2_ACCESS_KEY_ID           – R2 API token Access Key ID
 *   R2_SECRET_ACCESS_KEY       – R2 API token Secret Access Key
 *   R2_BUCKET_NAME             – R2 bucket name (e.g. teran-media)
 *   R2_PUBLIC_BASE_URL         – Public R2 URL (e.g. https://pub-xxx.r2.dev)
 *
 * How to get R2 API credentials:
 *   Cloudflare Dashboard → R2 → Manage R2 API Tokens → Create API Token
 *   Grant: Object Read & Write on bucket "teran-media"
 *   Copy Access Key ID + Secret Access Key.
 *
 * Run:
 *   ~/.nvm/versions/node/v22.17.0/bin/node scripts/backfill-icon-thumbs.mjs
 *
 * Idempotent: yes — skips rooms with icon_thumb_key already set.
 * Safe to stop: yes — each room is committed independently; restart resumes.
 */

import { createClient } from '../node_modules/@supabase/supabase-js/dist/module/index.js';
import { AwsClient } from '../node_modules/aws4fetch/dist/aws4fetch.esm.js';
import sharp from 'sharp';
import { randomUUID } from 'crypto';

// ── Config ──────────────────────────────────────────────────────────────────
const SUPABASE_URL            = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY    = process.env.SUPABASE_SERVICE_ROLE_KEY;
const CF_ACCOUNT_ID           = process.env.CF_ACCOUNT_ID;
const R2_ACCESS_KEY_ID        = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY    = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET               = process.env.R2_BUCKET_NAME   || 'teran-media';
const R2_PUBLIC_BASE          = (process.env.R2_PUBLIC_BASE_URL || '').replace(/\/$/, '');

const THUMB_MAX_SIDE          = 128;   // px — fits 44px display with 3× retina
const THUMB_QUALITY           = 82;    // JPEG quality
const PAGE_SIZE               = 20;    // rooms per batch
const DELAY_BETWEEN_MS        = 80;    // gentle rate limit between rooms

// ── Validation ───────────────────────────────────────────────────────────────
const missing = [
  ['SUPABASE_URL',             SUPABASE_URL],
  ['SUPABASE_SERVICE_ROLE_KEY',SUPABASE_SERVICE_KEY],
  ['CF_ACCOUNT_ID',            CF_ACCOUNT_ID],
  ['R2_ACCESS_KEY_ID',         R2_ACCESS_KEY_ID],
  ['R2_SECRET_ACCESS_KEY',     R2_SECRET_ACCESS_KEY],
  ['R2_PUBLIC_BASE_URL',       R2_PUBLIC_BASE],
].filter(([, v]) => !v).map(([k]) => k);

if (missing.length) {
  console.error('\n❌  Missing required env vars:\n  ' + missing.join('\n  '));
  console.error('\nSet them in .dev.vars or export before running.\n');
  process.exit(1);
}

// ── Clients ──────────────────────────────────────────────────────────────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

// aws4fetch signs requests for the Cloudflare R2 S3-compatible endpoint
const r2Endpoint = `https://${CF_ACCOUNT_ID}.r2.cloudflarestorage.com`;
const aws = new AwsClient({
  accessKeyId:     R2_ACCESS_KEY_ID,
  secretAccessKey: R2_SECRET_ACCESS_KEY,
  service:         's3',
  region:          'auto',
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Encode R2 key path segments (preserve slashes). */
function encodeKey(key) {
  return key.split('/').map(encodeURIComponent).join('/');
}

/** Fetch original image bytes from the public R2 URL. */
async function fetchOriginal(iconKey) {
  const url = `${R2_PUBLIC_BASE}/${encodeKey(iconKey)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Fetch original failed: ${res.status} ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

/** Resize to 128×128-fit JPEG using sharp. */
async function resizeToThumb(imageBuffer) {
  return sharp(imageBuffer)
    .resize(THUMB_MAX_SIDE, THUMB_MAX_SIDE, { fit: 'cover', position: 'centre' })
    .jpeg({ quality: THUMB_QUALITY, mozjpeg: false })
    .toBuffer();
}

/** Generate a unique R2 key for the thumb under image_thumb/ prefix. */
function makeThumbKey() {
  const ts = Date.now();
  const uuid = randomUUID().replace(/-/g, '');
  return `image_thumb/backfill/${ts}_${uuid}.jpg`;
}

/** Upload thumb buffer to R2 via S3-compatible signed PUT. */
async function uploadThumb(thumbBuffer, thumbKey) {
  const url = `${r2Endpoint}/${R2_BUCKET}/${encodeKey(thumbKey)}`;
  const signedReq = await aws.sign(url, {
    method: 'PUT',
    headers: {
      'Content-Type':   'image/jpeg',
      'Content-Length': String(thumbBuffer.byteLength),
    },
    body: thumbBuffer,
  });
  const res = await fetch(signedReq);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`R2 PUT failed: ${res.status} ${body}`);
  }
}

/** Write icon_thumb_key back to the rooms row via Supabase. */
async function patchRoom(roomId, thumbKey) {
  const { error } = await supabase
    .from('rooms')
    .update({ icon_thumb_key: thumbKey })
    .eq('id', roomId);
  if (error) throw new Error(`Supabase update failed: ${error.message}`);
}

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Main backfill loop ────────────────────────────────────────────────────────
async function run() {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   room icon_thumb_key backfill           ║');
  console.log(`║   bucket: ${R2_BUCKET.padEnd(30)} ║`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');

  let scanned = 0;
  let updated = 0;
  let skipped = 0;
  let failed  = 0;
  let offset  = 0;

  while (true) {
    // Fetch next page of rooms needing backfill
    const { data: rooms, error } = await supabase
      .from('rooms')
      .select('id, name, icon_key, icon_thumb_key')
      .not('icon_key', 'is', null)
      .or('icon_thumb_key.is.null,icon_thumb_key.eq.')  // NULL or empty string
      .range(offset, offset + PAGE_SIZE - 1)
      .order('id');

    if (error) {
      console.error('❌  Supabase query error:', error.message);
      process.exit(1);
    }

    if (!rooms || rooms.length === 0) {
      console.log('\n✅  No more rooms to process.\n');
      break;
    }

    console.log(`\n── Batch: rows ${offset}–${offset + rooms.length - 1} (${rooms.length} rooms) ──`);

    for (const room of rooms) {
      scanned++;
      const label = `  [${room.id}] \"${(room.name || '').slice(0, 30)}\"`;

      // Double-check: skip if already populated (race condition guard)
      if (room.icon_thumb_key && room.icon_thumb_key.trim().length > 0) {
        console.log(`${label}  ⏭  already has thumb — skip`);
        skipped++;
        continue;
      }

      if (!room.icon_key) {
        console.log(`${label}  ⏭  no icon_key — skip`);
        skipped++;
        continue;
      }

      try {
        // 1. Download original from public R2
        const originalBuf = await fetchOriginal(room.icon_key);
        const origKB = (originalBuf.byteLength / 1024).toFixed(1);

        // 2. Resize to 128px JPEG
        const thumbBuf = await resizeToThumb(originalBuf);
        const thumbKB = (thumbBuf.byteLength / 1024).toFixed(1);

        // 3. Upload thumb to R2
        const thumbKey = makeThumbKey();
        await uploadThumb(thumbBuf, thumbKey);

        // 4. Write key back to DB
        await patchRoom(room.id, thumbKey);

        updated++;
        console.log(`${label}  ✓  ${origKB}KB → ${thumbKB}KB  key=${thumbKey}`);
      } catch (err) {
        failed++;
        console.error(`${label}  ✗  ${err.message}`);
      }

      if (DELAY_BETWEEN_MS > 0) await sleep(DELAY_BETWEEN_MS);
    }

    // If fewer rows returned than PAGE_SIZE, we've reached the end
    // BUT: we must re-query from offset 0 because updated rows won't appear
    // in subsequent pages (icon_thumb_key is now set → filtered out).
    // So always reset offset to 0 for the next batch.
    if (rooms.length < PAGE_SIZE) {
      // Last page — done
      break;
    }
    // If we got a full page, some may have been skipped without updating.
    // Since updated rows are excluded from the query, we reset to offset 0
    // to pick up any that were skipped due to errors.
    offset = 0;
  }

  // ── Final summary ──────────────────────────────────────────────────────────
  console.log('');
  console.log('══════════════════════════════════════════');
  console.log(`  Scanned : ${scanned}`);
  console.log(`  Updated : ${updated}`);
  console.log(`  Skipped : ${skipped}`);
  console.log(`  Failed  : ${failed}`);
  console.log('══════════════════════════════════════════');
  console.log('');

  if (failed > 0) {
    console.warn(`⚠️   ${failed} room(s) failed. Rerun to retry — they will be picked up again.`);
    process.exit(1);
  } else {
    console.log('🎉  Backfill complete — all rooms now have icon_thumb_key.');
    process.exit(0);
  }
}

run().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
