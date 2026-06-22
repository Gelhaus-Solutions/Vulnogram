// Optional Redis cache + shared session backing store.
//
// Mirrors lib/mongo.js (a small singleton). Everything here is FAIL-OPEN: if
// Redis is not configured or is unreachable, get() misses, set()/del() are no-ops,
// and withCache() just runs the underlying function. The app keeps working, only
// uncached, so a Redis outage never takes the site down.

const crypto = require('crypto');

let Redis = null;
try {
    Redis = require('ioredis');
} catch (e) {
    Redis = null; // dependency not installed -> cache stays disabled
}

let client = null;
let connected = false;
let lastErrorLog = 0;

// Connect (idempotent). url empty / ioredis missing => cache disabled (no-op).
function connect(url) {
    if (client || !url || !Redis) {
        return client;
    }
    client = new Redis(url, {
        lazyConnect: true,
        enableOfflineQueue: false,   // fail fast instead of buffering when down
        maxRetriesPerRequest: 1,
        connectTimeout: 3000,
        retryStrategy: function (times) { return Math.min(times * 200, 5000); }
    });
    client.on('ready', function () { connected = true; });
    client.on('end', function () { connected = false; });
    client.on('close', function () { connected = false; });
    client.on('error', function (err) {
        connected = false;
        // Throttle so a down Redis doesn't flood the logs (and never throws: an
        // unhandled 'error' would otherwise crash the process).
        var now = Date.now();
        if (now - lastErrorLog > 30000) {
            lastErrorLog = now;
            console.warn('Redis cache unavailable (' + (err && err.message) + '); continuing uncached.');
        }
    });
    // Kick off the connection; a failure just leaves connected=false.
    client.connect().catch(function () { /* handled by 'error' above */ });
    return client;
}

function isConnected() {
    return connected;
}

function getClient() {
    return client;
}

async function get(key) {
    if (!connected || !client) {
        return null;
    }
    try {
        var raw = await client.get(key);
        return raw == null ? null : JSON.parse(raw);
    } catch (e) {
        return null; // treat any cache error as a miss
    }
}

async function set(key, value, ttlSeconds) {
    if (!connected || !client) {
        return;
    }
    try {
        var payload = JSON.stringify(value);
        if (ttlSeconds && ttlSeconds > 0) {
            await client.set(key, payload, 'EX', Math.floor(ttlSeconds));
        } else {
            await client.set(key, payload);
        }
    } catch (e) {
        /* swallow: caching is best-effort */
    }
}

async function del(key) {
    if (!connected || !client) {
        return;
    }
    try {
        await client.del(key);
    } catch (e) { /* swallow */ }
}

// Delete every key with the given prefix. Uses a non-blocking SCAN (never KEYS)
// so a large keyspace doesn't stall Redis. Best-effort.
function delByPrefix(prefix) {
    return new Promise(function (resolve) {
        if (!connected || !client) {
            return resolve();
        }
        try {
            var stream = client.scanStream({ match: prefix + '*', count: 200 });
            var pending = [];
            stream.on('data', function (keys) {
                if (keys && keys.length) {
                    pending.push(client.del.apply(client, keys).catch(function () {}));
                }
            });
            stream.on('end', function () { Promise.all(pending).then(resolve, resolve); });
            stream.on('error', function () { resolve(); });
        } catch (e) {
            resolve();
        }
    });
}

// Cache-aside helper. On a hit, returns the cached value; on a miss, runs fn(),
// stores the result (fire-and-forget) and returns it. When Redis is down, fn()
// runs directly so behaviour is identical to the no-cache path.
async function withCache(key, ttlSeconds, fn) {
    if (!connected || !client) {
        return fn();
    }
    var hit = await get(key);
    if (hit !== null) {
        return hit;
    }
    var fresh = await fn();
    if (fresh !== undefined && fresh !== null) {
        set(key, fresh, ttlSeconds); // do not await; don't block the response
    }
    return fresh;
}

// Deterministic JSON: sort object keys recursively so {a,b} and {b,a} collide.
function stableStringify(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(stableStringify).join(',') + ']';
    }
    var keys = Object.keys(value).sort();
    return '{' + keys.map(function (k) {
        return JSON.stringify(k) + ':' + stableStringify(value[k]);
    }).join(',') + '}';
}

// sha1 of a (stably-serialized) value, used to fingerprint the read-scope and the
// normalized query into a compact, fixed-length key segment.
function scopeFingerprint(obj) {
    return crypto.createHash('sha1').update(stableStringify(obj || {})).digest('hex');
}

// Build a cache key. Leading parts stay human-readable (so delByPrefix can target
// a section); the trailing object parts are hashed to keep keys bounded/legal.
function makeKey(parts) {
    return parts.map(function (p) {
        return (p !== null && typeof p === 'object') ? scopeFingerprint(p) : String(p);
    }).join(':');
}

async function close() {
    if (client) {
        try { await client.quit(); } catch (e) { /* ignore */ }
    }
    client = null;
    connected = false;
}

module.exports = {
    connect: connect,
    isConnected: isConnected,
    getClient: getClient,
    get: get,
    set: set,
    del: del,
    delByPrefix: delByPrefix,
    withCache: withCache,
    makeKey: makeKey,
    scopeFingerprint: scopeFingerprint,
    close: close
};
