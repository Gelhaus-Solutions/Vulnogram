// Thin accessor over the `teams` collection. Team documents are
//   { key, name, createdAt, settings }
// `key` is a slug used to reference the team from user.teams[].team and (later)
// from CVE documents. Used by the migration script and the instance-admin UI.

const mongo = require('../lib/mongo');

function collection() {
    return mongo.getCollection('teams');
}

// Stable, URL-safe team key derived from a name or legacy CNA/group email.
function slugifyTeamKey(input) {
    if (!input) {
        return '';
    }
    return String(input)
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .substring(0, 64);
}

function find(query, options) {
    return collection().find(query || {}, options || {}).toArray();
}

function findOne(query) {
    return collection().findOne(query || {});
}

function findByKey(key) {
    return collection().findOne({ key: key });
}

// Idempotently create a team by key; returns the (existing or new) team doc.
async function ensureTeam(key, name) {
    var k = slugifyTeamKey(key);
    if (!k) {
        return null;
    }
    await collection().updateOne(
        { key: k },
        { $setOnInsert: { key: k, name: name || k, createdAt: new Date(), settings: {} } },
        { upsert: true }
    );
    return collection().findOne({ key: k });
}

function insertOne(doc) {
    return collection().insertOne(doc);
}

function updateOne(query, update, options) {
    return collection().updateOne(query, update, options || {});
}

function deleteOne(query) {
    return collection().deleteOne(query);
}

module.exports = {
    slugifyTeamKey: slugifyTeamKey,
    find: find,
    findOne: findOne,
    findByKey: findByKey,
    ensureTeam: ensureTeam,
    insertOne: insertOne,
    updateOne: updateOne,
    deleteOne: deleteOne
};
