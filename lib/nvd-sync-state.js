// Persisted NVD sync status + backfill checkpoint, stored as a singleton doc in
// the nvd_sync_state collection. It lets the in-process scheduler:
//   - publish progress/status that the /admin/nvd panel reads, and
//   - resume an interrupted backfill (skip already-completed years) instead of
//     re-downloading everything from scratch.
// Mirrors the lib/nvd-stats.js singleton pattern. Every call is guarded so a
// disconnected/erroring DB degrades to a no-op rather than breaking a sync.

const mongo = require('./mongo');

const COLLECTION = 'nvd_sync_state';
const STATE_ID = 'nvd-sync';

function stateCollection() {
    return mongo.getCollection(COLLECTION);
}

async function get() {
    if (!mongo.isConnected()) {
        return null;
    }
    try {
        return await stateCollection().findOne({ _id: STATE_ID });
    } catch (e) {
        return null;
    }
}

// Shallow $set merge so callers can flush partial progress cheaply.
async function save(partial) {
    if (!mongo.isConnected()) {
        return null;
    }
    try {
        var set = Object.assign({}, partial, { updatedAt: new Date() });
        await stateCollection().updateOne({ _id: STATE_ID }, { $set: set }, { upsert: true });
        return set;
    } catch (e) {
        return null;
    }
}

async function markStart(reason, phase, config) {
    return save({
        running: true,
        phase: phase || 'sync',
        lastReason: reason,
        startedAt: new Date(),
        finishedAt: null,
        lastError: null,
        progress: null,
        config: config || null
    });
}

async function setProgress(progress) {
    return save({ progress: progress });
}

// Record a backfill year as complete (idempotent set union). Called only on the
// success path so a failed year is retried on the next run.
async function recordYearDone(year) {
    if (!mongo.isConnected()) {
        return null;
    }
    try {
        await stateCollection().updateOne(
            { _id: STATE_ID },
            {
                $addToSet: { 'checkpoint.years': year },
                $set: { 'checkpoint.updatedAt': new Date(), updatedAt: new Date() }
            },
            { upsert: true }
        );
    } catch (e) {
        return null;
    }
}

async function completedYears() {
    var doc = await get();
    var years = (doc && doc.checkpoint && Array.isArray(doc.checkpoint.years)) ? doc.checkpoint.years : [];
    return new Set(years);
}

async function markFinish(result, total) {
    return save({
        running: false,
        phase: 'idle',
        finishedAt: new Date(),
        lastResult: result || null,
        total: typeof total === 'number' ? total : null,
        progress: null
    });
}

async function markError(err) {
    return save({
        running: false,
        phase: 'idle',
        finishedAt: new Date(),
        lastError: { message: (err && err.message) ? err.message : String(err), at: new Date() },
        progress: null
    });
}

// Clear the backfill checkpoint so the next empty-collection run does a full
// re-backfill. (Admin "Force full re-backfill" action.)
async function reset() {
    if (!mongo.isConnected()) {
        return null;
    }
    try {
        await stateCollection().updateOne(
            { _id: STATE_ID },
            { $set: { 'checkpoint.years': [], 'checkpoint.updatedAt': new Date(), updatedAt: new Date() } },
            { upsert: true }
        );
    } catch (e) {
        return null;
    }
}

module.exports = {
    COLLECTION: COLLECTION,
    STATE_ID: STATE_ID,
    get: get,
    save: save,
    markStart: markStart,
    setProgress: setProgress,
    recordYearDone: recordYearDone,
    completedYears: completedYears,
    markFinish: markFinish,
    markError: markError,
    reset: reset
};
