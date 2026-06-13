// Applies the DB-backed instance settings (models/settings) as an overlay on top
// of the file-based config (config/conf.js). The conf object is a require-cache
// singleton shared by templates (app.locals.conf) and routes, so mutating its
// overridable keys in place makes new values appear everywhere — no restart.
//
// The original file defaults are snapshotted once at load, so clearing a setting
// in the UI falls back to the config/conf.js value rather than going blank.

const conf = require('../config/conf');
const settingsModel = require('../models/settings');

const defaults = {};
settingsModel.OVERRIDABLE.forEach(function (k) {
    defaults[k] = conf[k];
});
const nvdSyncDefaults = Object.assign({}, conf.nvdSync);

// Merge the stored settings document over the file defaults onto conf.
async function apply() {
    var doc = (await settingsModel.get()) || {};
    settingsModel.OVERRIDABLE.forEach(function (k) {
        var v = doc[k];
        conf[k] = (v !== undefined && v !== null && v !== '') ? v : defaults[k];
    });
    conf.nvdSync = Object.assign({}, nvdSyncDefaults, doc.nvdSync || {});
    return doc;
}

function getDefaults() {
    return Object.assign({}, defaults);
}

function getNvdSyncDefaults() {
    return Object.assign({}, nvdSyncDefaults);
}

module.exports = {
    apply: apply,
    getDefaults: getDefaults,
    getNvdSyncDefaults: getNvdSyncDefaults
};
