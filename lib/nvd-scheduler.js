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

module.exports = {
    start: start,
    restart: restart,
    get: get
};
