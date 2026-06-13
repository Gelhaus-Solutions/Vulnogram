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

// Built-in CVE Services endpoints, overridable via instance settings (item 7).
const DEFAULT_CVE_SERVICES = [
    { label: 'production', url: 'https://cveawg.mitre.org/api' },
    { label: 'test', url: 'https://cveawg-test.mitre.org/api' },
    { label: 'adp-test', url: 'https://cveawg-adp-test.mitre.org/api' },
    { label: 'local', url: 'http://127.0.0.1:3000/api' }
];
// Populate immediately so anything requiring conf before apply() still has a list.
if (!Array.isArray(conf.cveServices) || !conf.cveServices.length) {
    conf.cveServices = DEFAULT_CVE_SERVICES.slice();
}

// Merge the stored settings document over the file defaults onto conf.
async function apply() {
    var doc = (await settingsModel.get()) || {};
    settingsModel.OVERRIDABLE.forEach(function (k) {
        var v = doc[k];
        conf[k] = (v !== undefined && v !== null && v !== '') ? v : defaults[k];
    });
    conf.nvdSync = Object.assign({}, nvdSyncDefaults, doc.nvdSync || {});
    conf.cveServices = (Array.isArray(doc.cveServices) && doc.cveServices.length)
        ? doc.cveServices
        : DEFAULT_CVE_SERVICES.slice();
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
    getNvdSyncDefaults: getNvdSyncDefaults,
    DEFAULT_CVE_SERVICES: DEFAULT_CVE_SERVICES
};
