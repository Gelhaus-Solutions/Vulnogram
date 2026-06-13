// CVE editor templates: list/apply/create/delete, scoped to the user or a team.
// Mounted at /templates behind ensureAuthenticated.

const express = require('express');
const router = express.Router();
const csurf = require('csurf');
const csrfProtection = csurf();

const Template = require('../models/template');
const Team = require('../models/team');
const rbac = require('../lib/rbac');
const docAccess = require('../lib/doc-access');
const toErrorMessage = require('../lib/error-message');

const SECTION = 'cve5';

function userTeamKeys(user) {
    return docAccess.userTeamKeys(user);
}

// Templates a user may see: their own personal ones + their teams' shared ones.
function visibleQuery(user) {
    return {
        section: SECTION,
        $or: [
            { scope: 'user', owner: user.username },
            { scope: 'team', team: { $in: userTeamKeys(user) } }
        ]
    };
}

function canSee(user, t) {
    if (!t || t.section !== SECTION) {
        return false;
    }
    if (t.scope === 'user') {
        return t.owner === user.username;
    }
    return userTeamKeys(user).indexOf(t.team) >= 0;
}

function parseJSON(s) {
    try {
        return typeof s === 'string' ? JSON.parse(s) : (s || null);
    } catch (e) {
        return null;
    }
}

// List visible templates + the user's teams (for the save-scope picker).
router.get('/list/json', async function (req, res) {
    try {
        var templates = await Template.find(visibleQuery(req.user), { projection: { name: 1, scope: 1, team: 1 }, sort: { name: 1 } });
        var keys = userTeamKeys(req.user);
        var teams = keys.length ? await Team.find({ key: { $in: keys } }, { projection: { key: 1, name: 1 } }) : [];
        res.json({
            me: req.user.username,
            templates: templates.map(function (t) { return { id: String(t._id), name: t.name, scope: t.scope, team: t.team || null }; }),
            teams: teams.map(function (t) { return { key: t.key, name: t.name }; })
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to list templates' });
    }
});

// One template's selection + values (only if visible).
router.get('/:id/json', async function (req, res) {
    try {
        var t = await Template.findById(req.params.id);
        if (!canSee(req.user, t)) {
            return res.status(t ? 403 : 404).json({ error: t ? 'No access' : 'Not found' });
        }
        res.json({ id: String(t._id), name: t.name, selection: t.selection || {}, values: t.values || {} });
    } catch (err) {
        res.status(500).json({ error: 'Failed to load template' });
    }
});

// Create a template from the editor's current default-property settings.
router.post('/', csrfProtection, async function (req, res) {
    try {
        var name = (req.body.name || '').trim();
        if (name.length < 1 || name.length > 80) {
            return res.status(400).json({ type: 'err', msg: 'Template name must be 1-80 characters.' });
        }
        var scope = req.body.scope === 'team' ? 'team' : 'user';
        var team = null;
        if (scope === 'team') {
            team = req.body.team;
            if (userTeamKeys(req.user).indexOf(team) < 0) {
                return res.status(403).json({ type: 'err', msg: 'You are not a member of that team.' });
            }
        }
        var now = new Date();
        var doc = {
            name: name,
            section: SECTION,
            scope: scope,
            team: team,
            owner: req.user.username,
            createdBy: req.user.username,
            selection: parseJSON(req.body.selection) || {},
            values: parseJSON(req.body.values) || {},
            createdAt: now,
            updatedAt: now
        };
        var r = await Template.insertOne(doc);
        res.json({ type: 'ok', id: String(r.insertedId) });
    } catch (err) {
        res.status(500).json({ type: 'err', msg: toErrorMessage(err) });
    }
});

// Delete a template (own personal one, or a team one you created / can manage).
router.post('/:id/delete', csrfProtection, async function (req, res) {
    try {
        var t = await Template.findById(req.params.id);
        if (!t) {
            req.flash('error', 'Template not found.');
            return res.redirect('/templates');
        }
        var allowed = false;
        if (t.scope === 'user') {
            allowed = (t.owner === req.user.username);
        } else if (t.scope === 'team') {
            allowed = (t.createdBy === req.user.username) || rbac.can(req.user, rbac.CAPABILITIES.TEAM_MANAGE, { team: t.team });
        }
        if (!allowed) {
            res.status(403);
            req.flash('error', 'You cannot delete this template.');
            return res.redirect('/templates');
        }
        await Template.deleteById(req.params.id);
        req.flash('success', 'Template deleted.');
        res.redirect('/templates');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/templates');
    }
});

// Management page.
router.get('/', csrfProtection, async function (req, res) {
    try {
        var templates = await Template.find(visibleQuery(req.user), { sort: { scope: 1, name: 1 } });
        res.render('templates', { title: 'CVE templates', templates: templates, me: req.user.username, csrfToken: req.csrfToken() });
    } catch (err) {
        res.render('blank', { title: 'Error', message: 'Failed to load templates: ' + err.message });
    }
});

module.exports = router;
