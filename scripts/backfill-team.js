// One-time, idempotent backfill of the `team` field on team-scoped documents
// that have no owning team (legacy docs, or docs that lost their team via the
// old update path that only set team on $setOnInsert). A missing team is treated
// by lib/doc-access as "world-visible", so leaving these unassigned is also an
// access gap.
//
// The correct team for an arbitrary legacy doc cannot be inferred, so the team
// must be supplied explicitly by the operator.
//
// Usage:
//   node scripts/backfill-team.js --team <teamKey>                # apply to cve5
//   node scripts/backfill-team.js --team <teamKey> --collection cve5
//   node scripts/backfill-team.js --team <teamKey> --dry-run      # report only
//
// Only docs whose `team` is missing/null/'' are touched; existing teams are never
// changed. `visibility` and `sharedWith` are only filled when absent.

const mongo = require('../lib/mongo');
const Team = require('../models/team');
const config = require('../config/conf');

function argValue(flag) {
    var i = process.argv.indexOf(flag);
    return (i >= 0 && i + 1 < process.argv.length) ? process.argv[i + 1] : null;
}

const dryRun = process.argv.includes('--dry-run');
const teamKey = argValue('--team');
const collectionName = argValue('--collection') || 'cve5';

const noTeamFilter = { $or: [{ team: { $exists: false } }, { team: null }, { team: '' }] };

async function main() {
    if (!teamKey) {
        console.error('Error: --team <teamKey> is required (the team to assign unassigned docs to).');
        process.exit(1);
    }
    await mongo.connect(config.database);

    var team = await Team.findByKey(teamKey);
    if (!team) {
        console.error('Error: team "' + teamKey + '" not found. Create it first or pass an existing team key.');
        process.exit(1);
    }

    var coll = mongo.getCollection(collectionName);
    var count = await coll.countDocuments(noTeamFilter);
    console.log('[' + collectionName + '] ' + count + ' doc(s) with no owning team' +
        (count ? ' -> would assign team "' + teamKey + '"' : ''));

    if (count === 0) {
        console.log('Nothing to backfill.');
        return;
    }

    if (dryRun) {
        console.log('Dry run only — no changes written. Re-run without --dry-run to apply.');
        return;
    }

    // Set team always; fill visibility/sharedWith only when absent so an explicit
    // visibility is never clobbered.
    var r1 = await coll.updateMany(noTeamFilter, { $set: { team: teamKey } });
    var r2 = await coll.updateMany(
        { team: teamKey, visibility: { $exists: false } },
        { $set: { visibility: 'team' } }
    );
    var r3 = await coll.updateMany(
        { team: teamKey, sharedWith: { $exists: false } },
        { $set: { sharedWith: [] } }
    );
    console.log('Assigned team on ' + r1.modifiedCount + ' doc(s); set default visibility on ' +
        r2.modifiedCount + '; initialised sharedWith on ' + r3.modifiedCount + '.');
}

main()
    .then(function () { return mongo.close(); })
    .then(function () { process.exit(0); })
    .catch(function (err) {
        console.error('Backfill failed:', err);
        mongo.close().finally(function () { process.exit(1); });
    });
