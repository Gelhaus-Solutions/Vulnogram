// Capability-based RBAC engine for Vulnogram.
//
// Two scopes:
//   - instance-wide roles, stored on user.instanceRoles  (e.g. ["InstanceAdmin"])
//   - per-team roles,      stored on user.teams[] = [{ team, roles: [..] }]
//
// Roles are named bundles of capabilities, stored in the `roles` collection and
// editable by instance admins (item 2). A small in-process cache maps each role
// name to its capability Set so can()/requireCap() stay synchronous; it is loaded
// at boot (loadRoles) and refreshed after any role write (reloadRoles).

const mongo = require('./mongo');

const ROLES_COLLECTION = 'roles';
const WILDCARD = '*';

// Capability ids. Keep in sync with DEFAULT_ROLES below and the plan.
const CAPABILITIES = {
    INSTANCE_SETTINGS: 'instance.settings',
    USER_MANAGE: 'user.manage',
    ROLE_MANAGE: 'role.manage',
    TEAM_MANAGE: 'team.manage',
    NVD_MANAGE: 'nvd.manage',
    CVE_CREATE: 'cve.create',
    CVE_EDIT: 'cve.edit',
    CVE_DELETE: 'cve.delete',
    CVE_PUBLISH: 'cve.publish',
    CVE_READ: 'cve.read'
};

const ALL_CAPABILITIES = Object.keys(CAPABILITIES).map(function (k) {
    return CAPABILITIES[k];
});

// Built-in roles, seeded when the roles collection is empty. builtin:true just
// marks them as shipped defaults; instance admins can edit/clone them later.
const DEFAULT_ROLES = [
    { name: 'InstanceAdmin', scope: 'instance', builtin: true, capabilities: [WILDCARD] },
    { name: 'TeamAdmin', scope: 'team', builtin: true, capabilities: ['team.manage', 'cve.create', 'cve.edit', 'cve.delete', 'cve.publish', 'cve.read'] },
    { name: 'Editor', scope: 'team', builtin: true, capabilities: ['cve.create', 'cve.edit', 'cve.publish', 'cve.read'] },
    { name: 'Viewer', scope: 'team', builtin: true, capabilities: ['cve.read'] }
];

// roleName -> Set(capabilities)
var roleCapsCache = new Map();

function rolesCollection() {
    return mongo.getCollection(ROLES_COLLECTION);
}

async function ensureRolesSeeded() {
    var col = rolesCollection();
    var count = await col.countDocuments({});
    if (count === 0) {
        await col.insertMany(DEFAULT_ROLES.map(function (r) {
            return Object.assign({}, r, { capabilities: r.capabilities.slice() });
        }));
    }
}

async function loadRoles() {
    await ensureRolesSeeded();
    var roles = await rolesCollection().find({}).toArray();
    var next = new Map();
    for (var r of roles) {
        next.set(r.name, new Set(Array.isArray(r.capabilities) ? r.capabilities : []));
    }
    roleCapsCache = next;
    return roleCapsCache;
}

// Call after any role create/update/delete so checks see fresh capabilities.
function reloadRoles() {
    return loadRoles();
}

function addCapsForRoleNames(names, out) {
    if (!Array.isArray(names)) {
        return out;
    }
    for (var i = 0; i < names.length; i++) {
        var set = roleCapsCache.get(names[i]);
        if (set) {
            set.forEach(function (c) { out.add(c); });
        }
    }
    return out;
}

// Union of a user's capabilities. With teamKey: instance roles + that one team's
// membership roles. Without teamKey: instance roles + every team membership
// (answers "can the user do X in any team they belong to").
function effectiveCapabilities(user, teamKey) {
    var caps = new Set();
    if (!user || typeof user !== 'object') {
        return caps;
    }
    addCapsForRoleNames(user.instanceRoles, caps);
    if (Array.isArray(user.teams)) {
        for (var i = 0; i < user.teams.length; i++) {
            var membership = user.teams[i];
            if (!membership) {
                continue;
            }
            if (teamKey === undefined || teamKey === null || membership.team === teamKey) {
                addCapsForRoleNames(membership.roles, caps);
            }
        }
    }
    return caps;
}

function instanceCapabilities(user) {
    var caps = new Set();
    if (user && typeof user === 'object') {
        addCapsForRoleNames(user.instanceRoles, caps);
    }
    return caps;
}

function can(user, capability, context) {
    if (!user || !capability) {
        return false;
    }
    var teamKey = context && context.team !== undefined ? context.team : undefined;
    var caps = effectiveCapabilities(user, teamKey);
    return caps.has(WILDCARD) || caps.has(capability);
}

function isInstanceAdmin(user) {
    return instanceCapabilities(user).has(WILDCARD);
}

// Express middleware factory. getTeamKey(req) optionally resolves a team context
// (e.g. from a loaded document) for team-scoped capabilities.
function requireCap(capability, getTeamKey) {
    return function (req, res, next) {
        var teamKey;
        try {
            teamKey = typeof getTeamKey === 'function' ? getTeamKey(req) : undefined;
        } catch (e) {
            teamKey = undefined;
        }
        if (req.user && can(req.user, capability, { team: teamKey })) {
            return next();
        }
        res.status(403);
        return res.render('blank', {
            title: 'Forbidden',
            message: 'You do not have permission to perform this action.'
        });
    };
}

module.exports = {
    CAPABILITIES: CAPABILITIES,
    ALL_CAPABILITIES: ALL_CAPABILITIES,
    WILDCARD: WILDCARD,
    DEFAULT_ROLES: DEFAULT_ROLES,
    ensureRolesSeeded: ensureRolesSeeded,
    loadRoles: loadRoles,
    reloadRoles: reloadRoles,
    effectiveCapabilities: effectiveCapabilities,
    instanceCapabilities: instanceCapabilities,
    can: can,
    isInstanceAdmin: isInstanceAdmin,
    requireCap: requireCap
};
