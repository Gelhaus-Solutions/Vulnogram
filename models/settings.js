// Single-document `settings` collection holding instance-level overrides that an
// instance admin can edit at runtime. These overlay the file-based defaults in
// config/conf.js (see lib/instance-settings.js).
//
// Only the keys in OVERRIDABLE may be set from the UI. Operational/secret keys
// (database URL, ports, session secret, SSL) are intentionally NOT overridable.

const mongo = require('../lib/mongo');

const SETTINGS_ID = 'instance';
const OVERRIDABLE = ['orgName', 'groupName', 'contact', 'classification', 'copyright', 'homepage'];

function collection() {
    return mongo.getCollection('settings');
}

function get() {
    return collection().findOne({ _id: SETTINGS_ID });
}

async function save(values) {
    await collection().updateOne(
        { _id: SETTINGS_ID },
        { $set: values },
        { upsert: true }
    );
    return get();
}

module.exports = {
    SETTINGS_ID: SETTINGS_ID,
    OVERRIDABLE: OVERRIDABLE,
    collection: collection,
    get: get,
    save: save
};
