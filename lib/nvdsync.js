// Copyright (c) 2018 Chandan B N. All rights reserved.
//
// NVD CVE sync engine, shared by:
//   * the in-app scheduler (start(), wired into app.js) so the running Vulnogram
//     process keeps the local NVD copy fresh without an external cron job, and
//   * the scripts/nvdimport.js CLI for manual / one-off runs.
//
// Records are stored in the native NVD CVE API 2.0 shape (one document per CVE:
// { cve: { id, published, lastModified, descriptions[], metrics{...}, ... } },
// upserted by cve.id). Two data sources are used:
//   * Bulk backfill    -> fkie-cad/nvd-json-data-feeds mirror (per-year .json.xz)
//   * Incremental sync  -> NVD API 2.0 modified-since windows, or the mirror's
//                          CVE-modified feed (keyless, 8-day coverage).

const { spawn } = require('child_process');
const mongo = require('./mongo');
const nvdConf = require('../default/nvd/conf');
const syncState = require('./nvd-sync-state');

const COLLECTION = (nvdConf && nvdConf.conf && nvdConf.conf.collectionName) || 'nvds';
const API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const MIRROR_BASE = 'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download';
const USER_AGENT = 'Vulnogram-nvdsync/2.0 (+https://vulnogram.org)';
const ID_RE = /^CVE-\d{4}-\d{4,}$/;
const FIRST_YEAR = 1999;
const API_PAGE = 2000;                          // NVD CVE API 2.0 max resultsPerPage
const WINDOW_MS = 120 * 24 * 60 * 60 * 1000;    // NVD allows date ranges of <=120 days

function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function backoffMs(attempt) {
    return Math.min(60000, 6000 * Math.pow(2, attempt - 1));
}

function requestGap(apiKey) {
    return apiKey ? 700 : 6500; // stay under 50/30s (keyed) or 5/30s (anonymous)
}

function log() {
    console.log.apply(console, ['[nvd-sync]'].concat(Array.prototype.slice.call(arguments)));
}

function newStats() {
    return { processed: 0, upserted: 0, modified: 0, matched: 0, skipped: 0, errors: 0, sampleShown: false };
}

function summary(stats) {
    return 'processed=' + stats.processed
        + ' upserted=' + stats.upserted
        + ' modified=' + stats.modified
        + ' skipped=' + stats.skipped
        + ' errors=' + stats.errors;
}

// --- Normalization -------------------------------------------------------

// Coerce any supported item into a { cve: {...} } document, or null.
function wrap(item) {
    if (!item || typeof item !== 'object') {
        return null;
    }
    if (item.cve && typeof item.cve === 'object') {
        return item;            // already { cve: {...} } (NVD API 2.0 vulnerabilities[])
    }
    if (item.id) {
        return { cve: item };   // bare cve object (fkie-cad cve_items[] / single file)
    }
    return null;
}

// Accept: NVD API 2.0 response ({vulnerabilities:[{cve}]}), fkie-cad feed
// ({cve_items:[bare cve]}), a single bare cve, a single {cve}, or a raw array.
function toDocs(parsed) {
    let raw = [];
    if (Array.isArray(parsed)) {
        raw = parsed;
    } else if (parsed && Array.isArray(parsed.vulnerabilities)) {
        raw = parsed.vulnerabilities;
    } else if (parsed && Array.isArray(parsed.cve_items)) {
        raw = parsed.cve_items;
    } else if (parsed && (parsed.id || parsed.cve)) {
        raw = [parsed];
    }
    const docs = [];
    for (const item of raw) {
        const doc = wrap(item);
        if (doc && doc.cve && typeof doc.cve.id === 'string' && ID_RE.test(doc.cve.id)) {
            docs.push(doc);
        }
    }
    return { docs: docs, seen: raw.length };
}

// --- HTTP ----------------------------------------------------------------

async function nvdApiGet(params, apiKey) {
    const url = API_BASE + '?' + new URLSearchParams(params).toString();
    const headers = { 'User-Agent': USER_AGENT };
    if (apiKey) {
        headers.apiKey = apiKey;
    }
    const maxAttempts = 5;
    for (let attempt = 1; ; attempt++) {
        let resp;
        try {
            resp = await fetch(url, { headers: headers });
        } catch (err) {
            if (attempt >= maxAttempts) {
                throw err;
            }
            log('network error, retrying in', backoffMs(attempt) / 1000 + 's:', err.message);
            await sleep(backoffMs(attempt));
            continue;
        }
        if (resp.ok) {
            return await resp.json();
        }
        const retryable = resp.status === 403 || resp.status === 429 || resp.status >= 500;
        if (retryable && attempt < maxAttempts) {
            const ra = Number(resp.headers.get('retry-after'));
            const wait = Number.isFinite(ra) && ra > 0 ? ra * 1000 : backoffMs(attempt);
            log('HTTP', resp.status, '- retrying in', Math.round(wait / 1000) + 's');
            await sleep(wait);
            continue;
        }
        throw new Error('NVD API returned HTTP ' + resp.status + ' ' + resp.statusText);
    }
}

async function fetchBinary(url) {
    const maxAttempts = 4;
    for (let attempt = 1; ; attempt++) {
        let resp;
        try {
            resp = await fetch(url, { headers: { 'User-Agent': USER_AGENT }, redirect: 'follow' });
        } catch (err) {
            if (attempt >= maxAttempts) {
                throw err;
            }
            await sleep(backoffMs(attempt));
            continue;
        }
        if (resp.ok) {
            return Buffer.from(await resp.arrayBuffer());
        }
        if (resp.status === 404) {
            return null; // year out of range, etc.
        }
        if (resp.status >= 500 && attempt < maxAttempts) {
            await sleep(backoffMs(attempt));
            continue;
        }
        throw new Error('GET ' + url + ' returned HTTP ' + resp.status);
    }
}

// --- xz decompression ----------------------------------------------------
// Node's zlib cannot decode xz. Prefer the pure-WASM `xz-decompress` package;
// fall back to a system `xz -dc` binary if present.

let xzCtor;
let xzCtorTried = false;
async function loadXzCtor() {
    if (xzCtorTried) {
        return xzCtor;
    }
    xzCtorTried = true;
    try {
        const mod = await import('xz-decompress');
        // The package interops as CJS, so the class may sit on the namespace,
        // on default, or on the "module.exports" interop key depending on loader.
        xzCtor = mod.XzReadableStream
            || (mod.default && mod.default.XzReadableStream)
            || (mod['module.exports'] && mod['module.exports'].XzReadableStream)
            || null;
    } catch (err) {
        xzCtor = null;
    }
    return xzCtor;
}

// Whole-feed decompression to a single string was removed: a multi-GB feed blew
// V8's string cap and crashed the process. Decompression now streams via
// decompressXzToStream + streamFeedDocs (see below).

// --- Streaming feed parse (avoids the >512MB single-string crash) -----------
// The mirror feeds (CVE-all especially) decompress to multi-GB JSON. Building one
// JS string from that throws a fatal V8 error ("Check failed: i::kMaxInt >= len")
// that takes the whole process down. Instead we decompress to a Node stream and
// parse it incrementally with stream-json, upserting in batches and never holding
// the whole feed (string or object) in memory.

const { Readable } = require('stream');

// Decompress an .xz buffer to a Node Readable of bytes. Prefers the pure-WASM
// xz-decompress package (consistent with decompressXz), else a system `xz -dc`.
async function decompressXzToStream(buf) {
    const XzReadableStream = await loadXzCtor();
    if (XzReadableStream) {
        const webStream = new Blob([buf]).stream();
        return Readable.fromWeb(new XzReadableStream(webStream));
    }
    let child;
    try {
        child = spawn('xz', ['-dc']);
    } catch (err) {
        throw err;
    }
    const errChunks = [];
    child.stderr.on('data', function (c) { errChunks.push(c); });
    child.on('error', function (err) {
        const e = err.code === 'ENOENT'
            ? new Error('xz decompression unavailable: install the "xz-decompress" npm '
                + 'package (npm install xz-decompress) or a system "xz" binary, or use '
                + 'the API source for updates.')
            : err;
        child.stdout.destroy(e);
    });
    child.on('close', function (code) {
        if (code && code !== 0) {
            child.stdout.destroy(new Error('xz exited with code ' + code + ': '
                + Buffer.concat(errChunks).toString('utf8')));
        }
    });
    child.stdin.on('error', function () { /* ignore EPIPE if xz dies early */ });
    child.stdin.end(buf);
    return child.stdout;
}

// stream-json Pick filter: keep the records array regardless of which wrapper key
// the feed uses (NVD 2.0 "vulnerabilities" or fkie-cad "cve_items").
function isFeedArrayPath(stack) {
    return stack.length > 0 && (stack[0] === 'vulnerabilities' || stack[0] === 'cve_items');
}

// Parse a Readable of feed JSON incrementally, upserting valid CVE docs in batches
// via handleDocs. Returns { seen, kept }. Backpressure is natural: the for-await
// loop pauses the source while a batch is written.
async function streamFeedDocs(readable, col, opts, stats, label) {
    const { parser } = require('stream-json');
    const { pick } = require('stream-json/filters/Pick');
    const { streamArray } = require('stream-json/streamers/StreamArray');

    const pipeline = readable
        .pipe(parser())
        .pipe(pick({ filter: isFeedArrayPath }))
        .pipe(streamArray());

    let seen = 0;
    let kept = 0;
    let batch = [];
    const batchSize = opts.batch || 1000;
    try {
        for await (const entry of pipeline) {
            seen++;
            const doc = wrap(entry && entry.value);
            if (doc && doc.cve && typeof doc.cve.id === 'string' && ID_RE.test(doc.cve.id)) {
                kept++;
                batch.push(doc);
            }
            if (batch.length >= batchSize) {
                await handleDocs(col, batch, opts, stats, label);
                batch = [];
                if (reachedLimit(opts, stats)) {
                    break;
                }
            }
        }
        if (batch.length && !reachedLimit(opts, stats)) {
            await handleDocs(col, batch, opts, stats, label);
        }
    } finally {
        // Tear down the source (e.g. kill xz) if we stopped early.
        try { if (readable && readable.destroy) readable.destroy(); } catch (e) { /* ignore */ }
    }
    return { seen: seen, kept: kept };
}

// Download a mirror feed and stream-parse it. Returns { seen, kept }, or null on 404.
async function streamMirrorFeed(name, col, opts, stats, label) {
    const buf = await fetchBinary(MIRROR_BASE + '/' + name + '.json.xz');
    if (buf === null) {
        return null;
    }
    const stream = await decompressXzToStream(buf);
    return await streamFeedDocs(stream, col, opts, stats, label || name);
}

// --- Mongo writes --------------------------------------------------------

async function ensureIndexes(col) {
    try {
        await col.createIndex({ 'cve.id': 1 }, {
            unique: true,
            partialFilterExpression: { 'cve.id': { $exists: true } },
            name: 'cve_id_unique'
        });
        await col.createIndex({ 'cve.lastModified': 1 }, { name: 'cve_lastModified' });
        await col.createIndex({ 'cve.published': -1 }, { name: 'cve_published' });
    } catch (err) {
        log('warning: could not create indexes (' + err.message + '). Continuing without them.');
    }
}

async function writeBatch(col, ops, stats) {
    if (ops.length === 0) {
        return;
    }
    try {
        const res = await col.bulkWrite(ops, { ordered: false });
        stats.upserted += res.upsertedCount || 0;
        stats.modified += res.modifiedCount || 0;
        stats.matched += res.matchedCount || 0;
    } catch (err) {
        const r = err && err.result;
        if (r) {
            stats.upserted += r.nUpserted || (r.result && r.result.nUpserted) || 0;
            stats.modified += r.nModified || (r.result && r.result.nModified) || 0;
        }
        stats.errors += (err.writeErrors && err.writeErrors.length) || 1;
        log('warning: bulkWrite reported', (err.writeErrors && err.writeErrors.length) || '?', 'failed op(s):', err.message);
    }
}

// Persist (or, when col is null in a CLI dry-run, print) a batch of documents.
async function handleDocs(col, docs, opts, stats, label) {
    let toProcess = docs;
    if (stats.processed + toProcess.length > opts.limit) {
        toProcess = toProcess.slice(0, Math.max(0, opts.limit - stats.processed));
    }
    stats.processed += toProcess.length;

    if (!col) {
        if (!stats.sampleShown && toProcess.length) {
            console.log('--- sample document (' + (label || 'doc') + ') ---');
            console.log(JSON.stringify(toProcess[0], null, 2));
            console.log('--- end sample ---');
            stats.sampleShown = true;
        }
        return;
    }

    let ops = [];
    for (const doc of toProcess) {
        ops.push({
            updateOne: {
                filter: { 'cve.id': doc.cve.id },
                update: { $set: doc },
                upsert: true
            }
        });
        if (ops.length >= (opts.batch || 1000)) {
            await writeBatch(col, ops, stats);
            ops = [];
        }
    }
    await writeBatch(col, ops, stats);
}

function reachedLimit(opts, stats) {
    return stats.processed >= (opts.limit || Infinity);
}

// --- Sync operations -----------------------------------------------------

async function backfill(col, opts, stats) {
    if (opts.all) {
        log('backfill: downloading the full CVE-all feed (large, streamed)...');
        const r = await streamMirrorFeed('CVE-all', col, opts, stats, 'CVE-all');
        if (!r) {
            throw new Error('CVE-all feed not found on the mirror.');
        }
        stats.skipped += r.seen - r.kept;
        return;
    }

    let years;
    if (opts.year) {
        years = [opts.year];
    } else {
        const from = opts.from || FIRST_YEAR;
        const to = opts.to || new Date().getFullYear();
        years = [];
        for (let y = from; y <= to; y++) {
            years.push(y);
        }
    }

    for (let yi = 0; yi < years.length; yi++) {
        const year = years[yi];
        if (reachedLimit(opts, stats)) {
            break;
        }
        // Resume: skip years already completed in a previous (interrupted) run.
        if (opts.completedYears && opts.completedYears.has(year)) {
            log('year', year, '- already done (resuming), skipping');
            continue;
        }
        if (typeof opts.onProgress === 'function') {
            try { await opts.onProgress({ message: 'backfilling ' + year, current: yi + 1, total: years.length }); } catch (e) {}
        }
        // Resilient per-year: a transient download/parse failure for one year
        // must not abort a full backfill (which would leave nvds partially
        // populated and stop the empty-collection backfill from resuming).
        try {
            const r = await streamMirrorFeed('CVE-' + year, col, opts, stats, 'CVE-' + year);
            if (!r) {
                log('year', year, '- no feed (skipping)');
                continue;
            }
            stats.skipped += r.seen - r.kept;
            log('year', year + ':', r.kept, 'records',
                col ? '(upserted=' + stats.upserted + ' modified=' + stats.modified + ')' : '(dry-run)');
            // Record completion only on the success path so a failed year is retried.
            if (typeof opts.onYearDone === 'function') {
                try { await opts.onYearDone(year, stats); } catch (e) {}
            }
        } catch (err) {
            stats.errors++;
            log('year', year, '- failed:', err && err.message ? err.message : err);
        }
    }
}

// Optional, opt-in cleanup to cap collection growth. Off by default
// (pruneOlderThanYears = 0). Only called on a NON-empty collection outside the
// backfill phase, so a fresh backfill can never race it.
async function maybePrune(col, pruneOlderThanYears, stats) {
    if (!pruneOlderThanYears || pruneOlderThanYears <= 0 || !col) {
        return;
    }
    try {
        const cutoffYear = new Date().getFullYear() - pruneOlderThanYears;
        // cve.published is an ISO-8601 string; a lexical $lt on ISO strings is chronological.
        const cutoffISO = cutoffYear + '-01-01T00:00:00.000';
        const res = await col.deleteMany({ 'cve.published': { $lt: cutoffISO } });
        stats.pruned = (res && res.deletedCount) ? res.deletedCount : 0;
        log('pruned', stats.pruned, 'records published before', cutoffYear);
    } catch (e) {
        log('warning: prune failed:', e && e.message ? e.message : e);
    }
}

async function syncFeed(col, opts, stats, feedName) {
    const r = await streamMirrorFeed(feedName, col, opts, stats, feedName);
    if (!r) {
        throw new Error(feedName + ' feed not found on the mirror.');
    }
    stats.skipped += r.seen - r.kept;
    log(feedName + ':', r.kept, 'changed records');
}

async function newestLastModified(col) {
    const doc = await col.find({ 'cve.lastModified': { $exists: true } })
        .project({ 'cve.lastModified': 1 })
        .sort({ 'cve.lastModified': -1 })
        .limit(1)
        .next();
    return doc && doc.cve ? doc.cve.lastModified : null;
}

async function syncUpdate(col, opts, stats) {
    let start;
    if (opts.since) {
        start = new Date(opts.since);
    } else if (col) {
        const newest = await newestLastModified(col);
        if (!newest) {
            throw new Error('The "' + COLLECTION + '" collection has no NVD 2.0 records yet. '
                + 'Run a backfill first, or pass a start date.');
        }
        // Re-pull a 1 minute overlap so records modified on the boundary are not missed.
        start = new Date(new Date(newest).getTime() - 60 * 1000);
    } else {
        const days = opts.days && opts.days > 0 ? Math.min(opts.days, 120) : 7;
        start = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    }
    if (isNaN(start.getTime())) {
        throw new Error('Invalid start date: ' + opts.since);
    }

    const apiKey = opts.apiKey || '';
    const gap = requestGap(apiKey);
    const windowMs = opts.days && opts.days > 0 ? Math.min(opts.days, 120) * 24 * 60 * 60 * 1000 : WINDOW_MS;
    const now = Date.now();
    log('update: pulling records modified since', start.toISOString(),
        apiKey ? '(with API key)' : '(no API key - throttled, ~6s/request)');

    let windowStart = start.getTime();
    while (windowStart < now && !reachedLimit(opts, stats)) {
        const windowEnd = Math.min(now, windowStart + windowMs - 1000);
        const params = {
            lastModStartDate: new Date(windowStart).toISOString(),
            lastModEndDate: new Date(windowEnd).toISOString(),
            resultsPerPage: API_PAGE,
            startIndex: 0
        };
        let startIndex = 0;
        let total = Infinity;
        while (startIndex < total && !reachedLimit(opts, stats)) {
            params.startIndex = startIndex;
            const page = await nvdApiGet(params, apiKey);
            total = page.totalResults || 0;
            const r = toDocs(page);
            stats.skipped += r.seen - r.docs.length;
            await handleDocs(col, r.docs, opts, stats, 'api');
            const got = page.resultsPerPage || r.docs.length || 0;
            log('window', params.lastModStartDate.slice(0, 10), '..', params.lastModEndDate.slice(0, 10),
                '- startIndex', startIndex, 'of', total,
                col ? '(upserted=' + stats.upserted + ' modified=' + stats.modified + ')' : '(dry-run)');
            if (got <= 0) {
                break;
            }
            startIndex += got;
            if (startIndex < total) {
                await sleep(gap);
            }
        }
        windowStart = windowEnd + 1000;
        if (windowStart < now) {
            await sleep(gap);
        }
    }
}

async function importFile(col, opts, stats) {
    const fs = require('fs');
    const path = opts.file;
    if (!path || !fs.existsSync(path)) {
        throw new Error('File not found: ' + path);
    }
    // Stream-parse so a multi-GB feed never becomes one giant string (which would
    // crash V8). .xz is decompressed to a stream; plain JSON is read as a stream.
    let stream;
    if (path.endsWith('.xz')) {
        stream = await decompressXzToStream(fs.readFileSync(path));
    } else {
        stream = fs.createReadStream(path);
    }
    const r = await streamFeedDocs(stream, col, opts, stats, path);
    stats.skipped += r.seen - r.kept;
    log('file', path + ':', r.kept, 'valid of', r.seen, 'records');
}

async function importCve(col, opts, stats) {
    if (!opts.cve || !ID_RE.test(opts.cve)) {
        throw new Error('Invalid CVE id: ' + opts.cve);
    }
    const r = toDocs(await nvdApiGet({ cveId: opts.cve }, opts.apiKey || ''));
    stats.skipped += r.seen - r.docs.length;
    if (r.docs.length === 0) {
        log('no record returned for', opts.cve);
        return;
    }
    await handleDocs(col, r.docs, opts, stats, opts.cve);
}

// --- In-app scheduler ----------------------------------------------------
// Started from app.js after MongoDB connects. Keeps the local NVD copy fresh
// without an external cron job. Safe to call when disabled (no-op).

function resolveSyncConfig(conf) {
    const c = (conf && conf.nvdSync) || {};
    return {
        enabled: c.enabled !== undefined ? !!c.enabled : (process.env.NVD_SYNC === 'true'),
        intervalHours: Number(c.intervalHours) > 0 ? Number(c.intervalHours) : 12,
        backfillOnEmpty: c.backfillOnEmpty !== false,
        source: c.source === 'api' ? 'api' : 'mirror',
        apiKey: c.apiKey || process.env.NVD_API_KEY || '',
        initialDelaySeconds: Number.isFinite(Number(c.initialDelaySeconds)) ? Number(c.initialDelaySeconds) : 120,
        pruneOlderThanYears: Number(c.pruneOlderThanYears) > 0 ? Number(c.pruneOlderThanYears) : 0
    };
}

function start(options) {
    const conf = (options && options.conf) || require('../config/conf');
    const cfg = resolveSyncConfig(conf);
    if (!cfg.enabled) {
        return { stop: function () {} };
    }
    if (!mongo.isConnected()) {
        log('MongoDB is not connected; NVD scheduler not started.');
        return { stop: function () {} };
    }

    let running = false;
    const runOpts = { batch: 1000, apiKey: cfg.apiKey };

    async function runOnce(reason) {
        if (running) {
            log('a sync is already in progress; skipping', reason, 'run.');
            return;
        }
        running = true;
        const stats = newStats();
        const cfgSnap = {
            enabled: cfg.enabled,
            source: cfg.source,
            intervalHours: cfg.intervalHours,
            backfillOnEmpty: cfg.backfillOnEmpty,
            pruneOlderThanYears: cfg.pruneOlderThanYears
        };
        try {
            await syncState.markStart(reason, 'sync', cfgSnap);
            const col = mongo.getCollection(COLLECTION);
            await ensureIndexes(col);
            const count = await col.estimatedDocumentCount();
            if (count === 0) {
                if (!cfg.backfillOnEmpty) {
                    log('nvds is empty and backfillOnEmpty is disabled; skipping', reason, 'run.');
                    await syncState.markFinish({ ok: true, summary: 'skipped: empty collection, backfill disabled' }, 0);
                    return;
                }
                log('nvds is empty - running initial backfill from the mirror (this can take a while)...');
                await syncState.save({ phase: 'backfill' });
                const completed = await syncState.completedYears();
                if (completed.size) {
                    log('resuming backfill -', completed.size, 'year(s) already complete');
                }
                const backfillOpts = Object.assign({}, runOpts, {
                    completedYears: completed,
                    onYearDone: function (year) { return syncState.recordYearDone(year); },
                    onProgress: function (p) { return syncState.setProgress(p); }
                });
                await backfill(col, backfillOpts, stats);
            } else if (cfg.source === 'api') {
                await syncState.save({ phase: 'update' });
                await syncUpdate(col, runOpts, stats);
                await maybePrune(col, cfg.pruneOlderThanYears, stats);
            } else {
                // Keyless incremental: the mirror's modified feed covers the last 8 days.
                await syncState.save({ phase: 'feed' });
                await syncFeed(col, runOpts, stats, 'CVE-modified');
                await maybePrune(col, cfg.pruneOlderThanYears, stats);
            }
            log(reason, 'sync complete -', summary(stats));
            try {
                await require('./nvd-stats').computeAndStore();
                log(reason, 'nvd stats cache refreshed');
            } catch (statsErr) {
                log('warning: nvd stats refresh failed:', statsErr && statsErr.message ? statsErr.message : statsErr);
            }
            // Drop the Redis query cache for the NVD section so the freshly synced
            // data (and recomputed charts) is served immediately, not after TTL.
            try { await require('./cache').delByPrefix('q:nvd:'); } catch (e) { /* cache optional */ }
            let total = 0;
            try { total = await col.estimatedDocumentCount(); } catch (e) { total = 0; }
            await syncState.markFinish({ ok: true, summary: summary(stats) }, total);
        } catch (err) {
            log(reason, 'sync failed:', err && err.message ? err.message : err);
            await syncState.markError(err);
        } finally {
            running = false;
            try { await syncState.save({ running: false }); } catch (e) {}
        }
    }

    const initialTimer = setTimeout(function () { runOnce('startup'); }, cfg.initialDelaySeconds * 1000);
    const intervalTimer = setInterval(function () { runOnce('scheduled'); }, cfg.intervalHours * 60 * 60 * 1000);
    if (initialTimer.unref) { initialTimer.unref(); }
    if (intervalTimer.unref) { intervalTimer.unref(); }

    log('scheduler started: source=' + cfg.source,
        '| every ' + cfg.intervalHours + 'h',
        '| backfillOnEmpty=' + cfg.backfillOnEmpty,
        cfg.apiKey ? '| API key set' : '| no API key');

    return {
        stop: function () {
            clearTimeout(initialTimer);
            clearInterval(intervalTimer);
        },
        runOnce: runOnce
    };
}

module.exports = {
    COLLECTION: COLLECTION,
    FIRST_YEAR: FIRST_YEAR,
    toDocs: toDocs,
    ensureIndexes: ensureIndexes,
    backfill: backfill,
    syncUpdate: syncUpdate,
    syncFeed: syncFeed,
    importFile: importFile,
    importCve: importCve,
    newStats: newStats,
    summary: summary,
    start: start
};
