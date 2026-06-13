// One-time, idempotent migration from the legacy priv/group user model to the
// capability-based RBAC model (instanceRoles + per-team memberships).
//
// Usage:
//   node scripts/migrate-rbac.js            # apply changes
//   node scripts/migrate-rbac.js --dry-run  # report what would change, write nothing
//
// Mapping:
//   priv == 0  -> instanceRoles: ["InstanceAdmin"], team role: TeamAdmin
//   priv == 2  -> team role: Viewer   (legacy "read only")
//   otherwise  -> team role: Editor   (legacy "read/write")
// A user's `group` email becomes a team (key = slugified email). priv/group are
// left in place for one release. Users that already have `instanceRoles` are
// skipped, so the script is safe to re-run.

const mongo = require('../lib/mongo');
const rbac = require('../lib/rbac');
const User = require('../models/user');
const Team = require('../models/team');
const config = require('../config/conf');

const dryRun = process.argv.includes('--dry-run');

function teamRoleForPriv(priv) {
    if (Number(priv) === 0) return 'TeamAdmin';
    if (Number(priv) === 2) return 'Viewer';
    return 'Editor';
}

async function main() {
    await mongo.connect(config.database);

    // 1. Seed built-in roles.
    if (dryRun) {
        var existingRoles = await mongo.getCollection('roles').countDocuments({});
        console.log('[roles] ' + existingRoles + ' role(s) present' +
            (existingRoles === 0 ? ' -> would seed ' + rbac.DEFAULT_ROLES.length + ' built-in roles' : ''));
    } else {
        await rbac.ensureRolesSeeded();
        console.log('[roles] built-in roles ensured');
    }

    // 2. Migrate users.
    var users = await User.find({});
    var migrated = 0;
    var skipped = 0;
    var teamsSeen = {};

    for (var i = 0; i < users.length; i++) {
        var u = users[i];
        if (Array.isArray(u.instanceRoles)) {
            skipped++;
            continue; // already migrated
        }
        var instanceRoles = Number(u.priv) === 0 ? ['InstanceAdmin'] : [];
        var teams = [];
        var teamKey = u.group ? Team.slugifyTeamKey(u.group) : '';
        if (teamKey) {
            teams.push({ team: teamKey, roles: [teamRoleForPriv(u.priv)] });
            teamsSeen[teamKey] = u.group;
        }
        var active = u.active !== false;

        console.log('[user] ' + u.username +
            ': instanceRoles=' + JSON.stringify(instanceRoles) +
            ', teams=' + JSON.stringify(teams) +
            ', active=' + active +
            (u.priv !== undefined ? ' (from priv=' + u.priv + (u.group ? ', group=' + u.group : '') + ')' : ''));

        if (!dryRun) {
            if (teamKey) {
                await Team.ensureTeam(teamKey, u.group);
            }
            await mongo.getCollection('users').updateOne(
                { _id: u._id },
                { $set: { instanceRoles: instanceRoles, teams: teams, active: active } }
            );
        }
        migrated++;
    }

    var teamKeys = Object.keys(teamsSeen);
    console.log('---');
    console.log('Teams ' + (dryRun ? 'that would be ensured' : 'ensured') + ': ' +
        (teamKeys.length ? teamKeys.join(', ') : '(none)'));
    console.log('Users ' + (dryRun ? 'to migrate' : 'migrated') + ': ' + migrated +
        ', already migrated/skipped: ' + skipped);
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
