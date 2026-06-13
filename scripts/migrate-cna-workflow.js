// Migrate the internal CNA workflow to the expanded, nested (tabbed) shape and
// top up the built-in role capabilities with the new workflow caps.
//
// Usage:
//   node scripts/migrate-cna-workflow.js            # apply
//   node scripts/migrate-cna-workflow.js --dry-run  # report only
//
// - Restructures each cve5 doc's flat body.CNA_private into the nested shape
//   (people/triage/dates/checklist/notes); todo strings become {task, done}.
//   Idempotent: already-nested docs are skipped.
// - Adds cve.transition (+review/approve for TeamAdmin) to the built-in roles.

const mongo = require('../lib/mongo');
const workflow = require('../lib/cna-workflow');
const config = require('../config/conf');

const dryRun = process.argv.includes('--dry-run');
const COLLECTION = 'cve5';

async function topUpRoleCaps() {
    var roles = mongo.getCollection('roles');
    var updates = [
        { name: 'TeamAdmin', caps: ['cve.transition', 'cve.review', 'cve.approve'] },
        { name: 'Editor', caps: ['cve.transition'] }
    ];
    for (var i = 0; i < updates.length; i++) {
        var u = updates[i];
        if (!dryRun) {
            await roles.updateOne({ name: u.name }, { $addToSet: { capabilities: { $each: u.caps } } });
        }
        console.log('[roles] ' + (dryRun ? 'would add' : 'added') + ' [' + u.caps.join(', ') + '] to ' + u.name);
    }
}

async function migrateDocs() {
    var col = mongo.getCollection(COLLECTION);
    var cursor = col.find({ 'body.CNA_private': { $exists: true } });
    var migrated = 0, skipped = 0, total = 0;
    while (await cursor.hasNext()) {
        var doc = await cursor.next();
        total++;
        var cna = doc.body && doc.body.CNA_private;
        if (!cna || cna.people || cna.triage || cna.dates || cna.checklist || cna.notes) {
            skipped++;
            continue; // already nested or empty
        }
        var nested = workflow.normalize(cna);
        if (!dryRun) {
            await col.updateOne({ _id: doc._id }, { $set: { 'body.CNA_private': nested } });
        }
        migrated++;
    }
    console.log('[' + COLLECTION + '] ' + (dryRun ? 'would migrate' : 'migrated') + ' ' + migrated +
        ' of ' + total + ' doc(s) with CNA_private; skipped ' + skipped + ' (already nested).');
}

async function main() {
    await mongo.connect(config.database);
    await topUpRoleCaps();
    await migrateDocs();
    if (dryRun) {
        console.log('Dry run only — no changes written. Re-run without --dry-run to apply.');
    }
}

main()
    .then(function () { return mongo.close(); })
    .then(function () { process.exit(0); })
    .catch(function (err) {
        console.error('Migration failed:', err);
        mongo.close().finally(function () { process.exit(1); });
    });
