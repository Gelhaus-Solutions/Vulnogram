// Instance administration: settings overlay, custom roles, and teams.
// Mounted at /admin behind ensureAuthenticated; each area is further gated by a
// specific capability. User management lives in routes/users.js (linked from here).

const express = require('express');
const router = express.Router();
const csurf = require('csurf');
const csrfProtection = csurf();

const rbac = require('../lib/rbac');
const Role = require('../models/role');
const Team = require('../models/team');
const User = require('../models/user');
const settingsModel = require('../models/settings');
const instanceSettings = require('../lib/instance-settings');
const nvdScheduler = require('../lib/nvd-scheduler');
const nvdSyncState = require('../lib/nvd-sync-state');
const nvdStats = require('../lib/nvd-stats');
const conf = require('../config/conf');
const toErrorMessage = require('../lib/error-message');

const CAP = rbac.CAPABILITIES;
const ROLE_NAME_RE = /^[A-Za-z0-9 _-]{2,48}$/;
const TEAM_NAME_RE = /^.{2,64}$/;

// Parse a team's workflow stages from a textarea (one per line or comma-separated).
function parseStages(input) {
    if (!input || typeof input !== 'string') {
        return [];
    }
    return input.split(/[\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean).slice(0, 50);
}

// Parse the CVE Services endpoints textarea (one "label | https://..." per line).
function parseCveServices(input) {
    if (!input || typeof input !== 'string') {
        return [];
    }
    return input.split('\n').map(function (line) {
        line = line.trim();
        if (!line) { return null; }
        var parts = line.split('|');
        var label, url;
        if (parts.length >= 2) {
            label = parts[0].trim();
            url = parts.slice(1).join('|').trim();
        } else {
            url = line;
            label = line;
        }
        if (!/^https?:\/\//i.test(url)) { return null; }
        return { label: label.substring(0, 40), url: url.substring(0, 200) };
    }).filter(Boolean).slice(0, 20);
}

function hasAnyAdminCap(user) {
    return rbac.can(user, CAP.INSTANCE_SETTINGS) ||
        rbac.can(user, CAP.USER_MANAGE) ||
        rbac.can(user, CAP.ROLE_MANAGE) ||
        rbac.can(user, CAP.TEAM_MANAGE) ||
        rbac.can(user, CAP.NVD_MANAGE);
}

// Whole-area guard: must hold at least one administrative capability.
router.use(function (req, res, next) {
    res.locals.page = '/admin';
    if (!hasAnyAdminCap(req.user)) {
        res.status(403);
        return res.render('blank', {
            title: 'Forbidden',
            message: 'You do not have access to instance administration.'
        });
    }
    next();
});

// ---- Dashboard ----
router.get('/', function (req, res) {
    res.render('admin/dashboard', { title: 'Instance administration' });
});

// ---- Instance settings ----
router.get('/settings', rbac.requireCap(CAP.INSTANCE_SETTINGS), csrfProtection, async function (req, res) {
    var doc = (await settingsModel.get()) || {};
    res.render('admin/settings', {
        title: 'Instance settings',
        settings: doc,
        defaults: instanceSettings.getDefaults(),
        nvdSyncDefaults: instanceSettings.getNvdSyncDefaults(),
        conf: conf,
        csrfToken: req.csrfToken()
    });
});

router.post('/settings', rbac.requireCap(CAP.INSTANCE_SETTINGS), csrfProtection, async function (req, res) {
    try {
        var values = {};
        settingsModel.OVERRIDABLE.forEach(function (k) {
            values[k] = typeof req.body[k] === 'string' ? req.body[k].trim() : '';
        });
        var prevNvd = (conf.nvdSync && conf.nvdSync.enabled) + '|' + (conf.nvdSync && conf.nvdSync.intervalHours);
        values.nvdSync = {
            enabled: req.body.nvdEnabled === 'on' || req.body.nvdEnabled === 'true',
            intervalHours: Number(req.body.nvdIntervalHours) > 0
                ? Number(req.body.nvdIntervalHours)
                : (conf.nvdSync ? conf.nvdSync.intervalHours : 12)
        };
        values.cveServices = parseCveServices(req.body.cveServices);
        await settingsModel.save(values);
        await instanceSettings.apply();
        // Restart the in-app NVD scheduler only if its schedule actually changed.
        var nextNvd = (conf.nvdSync && conf.nvdSync.enabled) + '|' + (conf.nvdSync && conf.nvdSync.intervalHours);
        if (prevNvd !== nextNvd) {
            try { nvdScheduler.restart(); } catch (e) { console.error('NVD scheduler restart failed:', e.message); }
        }
        req.flash('success', 'Instance settings saved.');
        res.redirect('/admin/settings');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/settings');
    }
});

// ---- NVD sync status ----
router.get('/nvd', rbac.requireCap(CAP.NVD_MANAGE), csrfProtection, async function (req, res) {
    var state = await nvdSyncState.get();
    var stats = null;
    try { stats = await nvdStats.get(); } catch (e) { stats = null; }
    res.render('admin/nvd', {
        title: 'NVD sync',
        state: state,
        stats: stats,
        nvdSync: conf.nvdSync || {},
        csrfToken: req.csrfToken()
    });
});

router.post('/nvd/run', rbac.requireCap(CAP.NVD_MANAGE), csrfProtection, function (req, res) {
    try {
        var started = nvdScheduler.runNow('manual');
        if (started) {
            // Fire-and-forget; runOnce records its own outcome/errors in nvd_sync_state.
            if (typeof started.catch === 'function') { started.catch(function () {}); }
            req.flash('success', 'NVD sync started. Refresh this page to follow progress.');
        } else {
            req.flash('error', 'NVD sync is not enabled. Enable it in Instance settings first.');
        }
    } catch (err) {
        req.flash('error', toErrorMessage(err));
    }
    res.redirect('/admin/nvd');
});

router.post('/nvd/reset-checkpoint', rbac.requireCap(CAP.NVD_MANAGE), csrfProtection, async function (req, res) {
    try {
        await nvdSyncState.reset();
        req.flash('success', 'Backfill checkpoint cleared. The next empty-collection sync will re-download all years.');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
    }
    res.redirect('/admin/nvd');
});

// ---- Roles ----
function parseCapabilities(body) {
    var caps = [];
    if (body.wildcard === 'on' || body.wildcard === 'true') {
        caps.push(rbac.WILDCARD);
    }
    var picked = body.capabilities;
    if (typeof picked === 'string') { picked = [picked]; }
    if (Array.isArray(picked)) {
        picked.forEach(function (c) {
            if (rbac.ALL_CAPABILITIES.indexOf(c) >= 0 && caps.indexOf(c) < 0) {
                caps.push(c);
            }
        });
    }
    return caps;
}

router.get('/roles', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, async function (req, res) {
    var roles = await Role.find({}, { sort: { scope: 1, name: 1 } });
    res.render('admin/roles', { title: 'Roles', roles: roles, csrfToken: req.csrfToken() });
});

router.get('/roles/new', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, function (req, res) {
    res.render('admin/role-edit', {
        title: 'New role',
        role: { name: '', scope: 'team', capabilities: [], builtin: false },
        isNew: true,
        allCapabilities: rbac.ALL_CAPABILITIES,
        wildcard: rbac.WILDCARD,
        csrfToken: req.csrfToken()
    });
});

router.post('/roles/new', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, async function (req, res) {
    try {
        var name = (req.body.name || '').trim();
        if (!ROLE_NAME_RE.test(name)) {
            req.flash('error', 'Role name must be 2-48 chars (letters, numbers, space, _ or -).');
            return res.redirect('/admin/roles/new');
        }
        if (await Role.findByName(name)) {
            req.flash('error', 'A role named "' + name + '" already exists.');
            return res.redirect('/admin/roles/new');
        }
        var scope = req.body.scope === 'instance' ? 'instance' : 'team';
        await Role.insertOne({ name: name, scope: scope, capabilities: parseCapabilities(req.body), builtin: false });
        await rbac.reloadRoles();
        req.flash('success', 'Role "' + name + '" created.');
        res.redirect('/admin/roles');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/roles/new');
    }
});

router.get('/roles/:name', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, async function (req, res) {
    var role = await Role.findByName(req.params.name);
    if (!role) {
        req.flash('error', 'Role not found.');
        return res.redirect('/admin/roles');
    }
    res.render('admin/role-edit', {
        title: 'Edit role: ' + role.name,
        role: role,
        isNew: false,
        allCapabilities: rbac.ALL_CAPABILITIES,
        wildcard: rbac.WILDCARD,
        csrfToken: req.csrfToken()
    });
});

router.post('/roles/:name', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, async function (req, res) {
    try {
        var role = await Role.findByName(req.params.name);
        if (!role) {
            req.flash('error', 'Role not found.');
            return res.redirect('/admin/roles');
        }
        var scope = req.body.scope === 'instance' ? 'instance' : 'team';
        await Role.updateOne({ name: role.name }, { $set: { scope: scope, capabilities: parseCapabilities(req.body) } });
        await rbac.reloadRoles();
        req.flash('success', 'Role "' + role.name + '" updated.');
        res.redirect('/admin/roles');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/roles/' + encodeURIComponent(req.params.name));
    }
});

router.post('/roles/:name/delete', rbac.requireCap(CAP.ROLE_MANAGE), csrfProtection, async function (req, res) {
    try {
        var role = await Role.findByName(req.params.name);
        if (!role) {
            req.flash('error', 'Role not found.');
            return res.redirect('/admin/roles');
        }
        if (role.builtin) {
            req.flash('error', 'Built-in roles cannot be deleted (you can edit them instead).');
            return res.redirect('/admin/roles');
        }
        var inUse = await User.find({ $or: [{ instanceRoles: role.name }, { 'teams.roles': role.name }] }, ['username']);
        if (inUse && inUse.length) {
            req.flash('error', 'Role "' + role.name + '" is assigned to ' + inUse.length + ' user(s); unassign it before deleting.');
            return res.redirect('/admin/roles');
        }
        await Role.deleteOne({ name: role.name });
        await rbac.reloadRoles();
        req.flash('success', 'Role "' + role.name + '" deleted.');
        res.redirect('/admin/roles');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/roles');
    }
});

// ---- Teams ----
router.get('/teams', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, async function (req, res) {
    var teams = await Team.find({}, { sort: { key: 1 } });
    res.render('admin/teams', { title: 'Teams', teams: teams, csrfToken: req.csrfToken() });
});

router.get('/teams/new', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, function (req, res) {
    res.render('admin/team-edit', { title: 'New team', team: { key: '', name: '' }, isNew: true, csrfToken: req.csrfToken() });
});

router.post('/teams/new', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, async function (req, res) {
    try {
        var name = (req.body.name || '').trim();
        if (!TEAM_NAME_RE.test(name)) {
            req.flash('error', 'Team name must be 2-64 characters.');
            return res.redirect('/admin/teams/new');
        }
        var key = Team.slugifyTeamKey(req.body.key || name);
        if (!key) {
            req.flash('error', 'Could not derive a team key from the name.');
            return res.redirect('/admin/teams/new');
        }
        if (await Team.findByKey(key)) {
            req.flash('error', 'A team with key "' + key + '" already exists.');
            return res.redirect('/admin/teams/new');
        }
        await Team.insertOne({ key: key, name: name, createdAt: new Date(), settings: { stages: parseStages(req.body.stages) } });
        req.flash('success', 'Team "' + name + '" created.');
        res.redirect('/admin/teams');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/teams/new');
    }
});

router.get('/teams/:key', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, async function (req, res) {
    var team = await Team.findByKey(req.params.key);
    if (!team) {
        req.flash('error', 'Team not found.');
        return res.redirect('/admin/teams');
    }
    res.render('admin/team-edit', { title: 'Edit team: ' + team.name, team: team, isNew: false, csrfToken: req.csrfToken() });
});

router.post('/teams/:key', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, async function (req, res) {
    try {
        var team = await Team.findByKey(req.params.key);
        if (!team) {
            req.flash('error', 'Team not found.');
            return res.redirect('/admin/teams');
        }
        var name = (req.body.name || '').trim();
        if (!TEAM_NAME_RE.test(name)) {
            req.flash('error', 'Team name must be 2-64 characters.');
            return res.redirect('/admin/teams/' + encodeURIComponent(team.key));
        }
        await Team.updateOne({ key: team.key }, { $set: { name: name, 'settings.stages': parseStages(req.body.stages) } });
        req.flash('success', 'Team "' + name + '" updated.');
        res.redirect('/admin/teams');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/teams');
    }
});

router.post('/teams/:key/delete', rbac.requireCap(CAP.TEAM_MANAGE), csrfProtection, async function (req, res) {
    try {
        var team = await Team.findByKey(req.params.key);
        if (!team) {
            req.flash('error', 'Team not found.');
            return res.redirect('/admin/teams');
        }
        var inUse = await User.find({ 'teams.team': team.key }, ['username']);
        if (inUse && inUse.length) {
            req.flash('error', 'Team "' + team.key + '" has ' + inUse.length + ' member(s); remove them before deleting.');
            return res.redirect('/admin/teams');
        }
        await Team.deleteOne({ key: team.key });
        req.flash('success', 'Team "' + team.name + '" deleted.');
        res.redirect('/admin/teams');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/admin/teams');
    }
});

module.exports = router;
