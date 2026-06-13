// Server-side CVE editor templates: named bundles of a default-property
// "selection" (which fields show on new entries) + preset "values", scoped to a
// user ("personal") or a team ("shared"). Promotes the former browser-only
// default-properties cache (default/cve5/preload.js) to a sharable collection.

const mongo = require('../lib/mongo');
const { ObjectId } = require('mongodb');

function collection() {
    return mongo.getCollection('templates');
}

function toId(id) {
    try {
        return new ObjectId(id);
    } catch (e) {
        return null;
    }
}

function find(query, options) {
    return collection().find(query || {}, options || {}).toArray();
}

function findById(id) {
    var oid = toId(id);
    return oid ? collection().findOne({ _id: oid }) : Promise.resolve(null);
}

function insertOne(doc) {
    return collection().insertOne(doc);
}

function deleteById(id) {
    var oid = toId(id);
    return oid ? collection().deleteOne({ _id: oid }) : Promise.resolve({ deletedCount: 0 });
}

module.exports = {
    collection: collection,
    toId: toId,
    find: find,
    findById: findById,
    insertOne: insertOne,
    deleteById: deleteById
};
