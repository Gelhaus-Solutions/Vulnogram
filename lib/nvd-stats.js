// Precomputed NVD facet/chart statistics. The /nvd list page would otherwise
// recompute ~7 chart aggregations (including an expensive CPE-unwind "vendor"
// chart) over the whole nvds collection on every load. Instead we compute them
// once per sync into the nvd_stats collection and serve them from there, so the
// page loads in well under a second.

const mongo = require('./mongo');
const nvdConf = require('../default/nvd/conf.js');

const COLLECTION = (nvdConf && nvdConf.conf && nvdConf.conf.collectionName) || 'nvds';
const STATS_ID = 'nvd';

// Build {chartKey: pipeline} from the chart facets in default/nvd/conf.js, reusing
// their exact pipelines so cached charts match the facet definitions.
function chartPipelines() {
    var facets = (nvdConf && nvdConf.facet) || {};
    var out = {};
    for (var key in facets) {
        var f = facets[key];
        if (f && f.chart) {
            out[key] = Array.isArray(f.pipeline) ? f.pipeline : [{ $sortByCount: '$' + f.path }];
        }
    }
    return out;
}

function statsCollection() {
    return mongo.getCollection('nvd_stats');
}

// Run each chart pipeline over the whole collection and store the results.
async function computeAndStore() {
    if (!mongo.isConnected()) {
        return null;
    }
    var col = mongo.getCollection(COLLECTION);
    var pipelines = chartPipelines();
    var charts = {};
    for (var key in pipelines) {
        try {
            charts[key] = await col.aggregate(pipelines[key], { allowDiskUse: true }).toArray();
        } catch (e) {
            charts[key] = [];
        }
    }
    var total = 0;
    try {
        total = await col.estimatedDocumentCount();
    } catch (e) {
        total = 0;
    }
    var doc = { _id: STATS_ID, charts: charts, total: total, updatedAt: new Date() };
    await statsCollection().replaceOne({ _id: STATS_ID }, doc, { upsert: true });
    return doc;
}

function get() {
    return statsCollection().findOne({ _id: STATS_ID });
}

// Compute only when there are no cached stats yet or they are older than maxAgeMs.
// Safe to call without awaiting (best-effort background refresh).
async function refreshIfStale(maxAgeMs) {
    try {
        var existing = await get();
        var fresh = existing && existing.updatedAt &&
            (Date.now() - new Date(existing.updatedAt).getTime()) < maxAgeMs;
        if (fresh) {
            return existing;
        }
        return await computeAndStore();
    } catch (e) {
        return null;
    }
}

module.exports = {
    COLLECTION: COLLECTION,
    STATS_ID: STATS_ID,
    chartPipelines: chartPipelines,
    computeAndStore: computeAndStore,
    get: get,
    refreshIfStale: refreshIfStale
};
