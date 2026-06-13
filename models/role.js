// Thin accessor over the `roles` collection. Role documents are
//   { name, scope: "instance"|"team", capabilities: [String], builtin: Boolean }
// The capability semantics live in lib/rbac.js; this is just CRUD used by the
// migration script and the instance-admin UI (item 2).

const mongo = require('../lib/mongo');

function collection() {
    return mongo.getCollection('roles');
}

function find(query, options) {
    return collection().find(query || {}, options || {}).toArray();
}

function findOne(query) {
    return collection().findOne(query || {});
}

function findByName(name) {
    return collection().findOne({ name: name });
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
    find: find,
    findOne: findOne,
    findByName: findByName,
    insertOne: insertOne,
    updateOne: updateOne,
    deleteOne: deleteOne
};
