// Thin singleton wrapper around lib/nvdsync.start() so the NVD scheduler can be
// (re)started at runtime when an instance admin changes the nvdSync settings.
// nvdsync.start() reads conf.nvdSync, which lib/instance-settings.apply() refreshes
// before restart() is called.

const nvdsync = require('./nvdsync');
const conf = require('../config/conf');

let handle = null;

function start() {
    handle = nvdsync.start({ conf });
    return handle;
}

function restart() {
    if (handle && typeof handle.stop === 'function') {
        handle.stop();
    }
    return start();
}

function get() {
    return handle;
}

// Trigger a sync immediately (admin "Run sync now"). Fire-and-forget: the
// scheduler's own `running` guard prevents overlap with a scheduled run.
// Returns the runOnce promise, or null when the scheduler is not active
// (NVD sync disabled / DB not connected at startup).
function runNow(reason) {
    if (handle && typeof handle.runOnce === 'function') {
        return handle.runOnce(reason || 'manual');
    }
    return null;
}

module.exports = {
    start: start,
    restart: restart,
    get: get,
    runNow: runNow
};
