// Copyright (c) 2017 Chandan B N. All rights reserved.

// user management.

const express = require('express');
const protected = express.Router();
const public = express.Router();
const crypto = require('crypto');
const passport = require('passport');
const pbkdf2 = require('../lib/pbkdf2.js');
const toErrorMessage = require('../lib/error-message');
const User = require('../models/user');
const rbac = require('../lib/rbac');
const Team = require('../models/team');
const Role = require('../models/role');
const conf = require('../config/conf');
const { normalizePortalUrl } = require('../lib/portal-url');
const csurf = require('csurf');
const {
    matchedData,
    check,
    validationResult
} = require('express-validator');

const validator = require('validator');
var csrfProtection = csurf();
const profileRoutes = ['/profile', '/profile/:id'];

// Users who share at least one team with the given user (for the CVE owner picker).
// Falls back to just the user when they have no team memberships yet.
function teammateQuery(user) {
    var teamKeys = Array.isArray(user.teams)
        ? user.teams.map(function (t) { return t && t.team; }).filter(Boolean)
        : [];
    if (teamKeys.length) {
        return { 'teams.team': { $in: teamKeys } };
    }
    return { username: user.username };
}

// Role/team definitions an admin assigns from the edit form.
async function loadAssignmentDefs(admin) {
    if (!admin) {
        return { instanceRoleDefs: [], teamRoleDefs: [], teamDefs: [] };
    }
    try {
        return {
            instanceRoleDefs: await Role.find({ scope: 'instance' }, { sort: { name: 1 } }),
            teamRoleDefs: await Role.find({ scope: 'team' }, { sort: { name: 1 } }),
            teamDefs: await Team.find({}, { sort: { key: 1 } })
        };
    } catch (e) {
        return { instanceRoleDefs: [], teamRoleDefs: [], teamDefs: [] };
    }
}

// If admin allow edits, otherwise display user
protected.get(profileRoutes, csrfProtection, async function (req, res) {
    var admin = rbac.can(req.user, 'user.manage');
    var defs = await loadAssignmentDefs(admin);
    function renderEdit(profile, title) {
        res.render('users/edit', Object.assign({
            title: title,
            profile: profile,
            admin: admin,
            page: 'users',
            csrfToken: req.csrfToken()
        }, defs));
    }
    if (req.params.id) {
        if (!validator.matches(req.params.id, new RegExp('^' + conf.usernameRegex + '$'))) {
            req.flash('error', 'Invalid user id');
            res.render('blank');
            return;
        }
        var user = await User.findOne({ username: req.params.id });
        if (user) {
            //if Admin or self then present edit form
            if (admin || req.user.username == req.params.id) {
                renderEdit(user, 'Update profile: ' + user.username);
            } else {
                res.render('users/view', {
                    title: 'Profile: ' + user.username,
                    profile: user,
                    admin: admin,
                    page: 'users',
                    csrfToken: req.csrfToken()
                });
            }
        } else {
            req.flash('error', 'User id not found');
            if (admin) {
                res.redirect('/users/profile');
            } else {
                res.render('blank');
            }
        }
    } else {
        if (admin) {
            renderEdit({}, 'Add new user');
        } else {
            req.flash('error', 'Only administrators can add new users');
            res.render('blank');
        }
    }
});

// Register or update an user
protected.post(profileRoutes, csrfProtection, [
    check('name')
        .trim()
        .isLength({
        min: 2,
        max: undefined
    })
        .withMessage('Name too short')
        .isLength({
        min: 0,
        max: 64
    })
        .withMessage('Name too long'),
    check('emoji')
        .trim()
        .isLength({
        min: 0,
        max: 8
    })
        .withMessage('Long Emoji strings are not allowed'),
    check('email')
        .trim()
        .isEmail()
        .normalizeEmail()
        .isLength({
        min: 2,
        max: 256
    })
        .withMessage('User email is invalid'),
    check('password')
        .custom((value, {
        req
    }) => value === req.body.password2)
        .withMessage('Passwords do not match'),
    check('username')
        .trim()
        .custom((value, {
        req
    }) => {
        // validate username only for admins; usernames from unprivileged users are ignored
        if (!rbac.can(req.user, 'user.manage') || validator.matches(value, /^[a-zA-Z0-9]{3,128}$/)) {
            return true;
        }
        req.body.username = "";
        return false;
    })
        .withMessage('Username is invalid'),
    check('username')
        .custom((value, {
        req
    }) => {
        return User.findOne({
            username: value
        }).then((user) => {
            if ((!req.params.id || req.params.id != value) && user) {
                throw new Error('this username is already in use');
                return false;
            } else {
                return true;
            }
        });
    }),
], async function (req, res) {
    if (req.isAuthenticated()) {
        var admin = rbac.can(req.user, 'user.manage');
        let errors = validationResult(req);
        let updates = matchedData(req);

        if (!errors.isEmpty()) {
            for (var e of errors.array()) {
                req.flash('error', 'Error: ' + e.msg);
            }
            var defs = await loadAssignmentDefs(admin);
            // todo, clear invalid username or change form action uri
            res.render('users/edit', Object.assign({
                title: 'User ' + req.body.username,
                profile: req.body,
                admin: admin,
                page: 'users',
                csrfToken: req.csrfToken()
            }, defs));

            //res.redirect('/users/profile/'+req.user.username);
        } else {
            if (!admin) {
                updates.username = req.user.username;
                updates.instanceRoles = req.user.instanceRoles || [];
                updates.teams = req.user.teams || [];
                updates.active = req.user.active !== false;
            } else {
                // Instance roles (checkboxes) — keep only known instance-scoped role names.
                var instRoleDefs = await Role.find({ scope: 'instance' }, { sort: { name: 1 } });
                var instRoleNames = instRoleDefs.map(function (r) { return r.name; });
                var pickedInstance = req.body.instanceRoles;
                if (typeof pickedInstance === 'string') { pickedInstance = [pickedInstance]; }
                if (!Array.isArray(pickedInstance)) { pickedInstance = []; }
                updates.instanceRoles = pickedInstance.filter(function (r) { return instRoleNames.indexOf(r) >= 0; });

                // Per-team role selection posted as teamRole[<teamKey>] = <roleName|''>.
                var teamRoleMap = (req.body.teamRole && typeof req.body.teamRole === 'object') ? req.body.teamRole : {};
                var teams = [];
                Object.keys(teamRoleMap).forEach(function (k) {
                    var roleName = (teamRoleMap[k] || '').trim();
                    if (roleName) { teams.push({ team: k, roles: [roleName] }); }
                });
                updates.teams = teams;
                updates.active = (req.body.active === 'on' || req.body.active === 'true');

                // Guard: never remove the last active instance administrator.
                var adminRoleDefs = await Role.find({ capabilities: rbac.WILDCARD }, { projection: { name: 1 } });
                var adminRoleNames = adminRoleDefs.map(function (r) { return r.name; });
                var existingUser = await User.findOne({ username: updates.username });
                var wasAdmin = existingUser && existingUser.active !== false &&
                    (existingUser.instanceRoles || []).some(function (r) { return adminRoleNames.indexOf(r) >= 0; });
                var willBeAdmin = updates.active &&
                    updates.instanceRoles.some(function (r) { return adminRoleNames.indexOf(r) >= 0; });
                if (wasAdmin && !willBeAdmin) {
                    var otherAdmins = await User.find({
                        username: { $ne: existingUser.username },
                        active: { $ne: false },
                        instanceRoles: { $in: adminRoleNames }
                    }, ['username']);
                    if (!otherAdmins || otherAdmins.length === 0) {
                        req.flash('error', 'Cannot remove the last active instance administrator.');
                        return res.redirect('/users/profile/' + existingUser.username);
                    }
                }
            }
            let query = {
                username: updates.username
            };
            let updateOptions = {
                upsert: true,
                setDefaultsOnInsert: true
            };
            var updateResponse = function (err, doc) {
                if (err) {
                    req.flash('error', toErrorMessage(err));
                    res.redirect('/users/profile/' + updates.username);
                } else {
                    var msg = 'New user ' + updates.username + ' created';
                    if (doc) {
                        msg = 'Updated ' + updates.username;
                    }
                    req.flash('success', msg);
                    res.redirect('/users/profile/' + updates.username);
                }
            };
            if (updates.password) {
                pbkdf2.hash(updates.password, function (err, hash) {
                    if (err) {
                        console.error(err);
                    }
                    updates.password = hash;
                    User.findOneAndUpdate(query, updates, updateOptions, updateResponse);
                });
            } else {
                delete updates.password;
                User.findOneAndUpdate(query, updates, updateOptions, updateResponse);
            }
        }
    } else {
        req.flash('error', 'Authentication required!');
        res.redirect('/users/login');
    }
});

protected.get('/delete/:id', csrfProtection, function (req, res) {
    if (!validator.matches(req.params.id, new RegExp('^' + conf.usernameRegex + '$'))) {
        req.flash('error', 'Invalid user id');
        res.render('blank');
        return;
    }
    req.flash('warning', 'Deleting users is not yet implemented. Fow now, users can be deleted in the backend database.');
    res.render('blank');
});

// Login form
public.get('/login', csrfProtection, function (req, res) {
    res.render('users/login', {
        title: 'Vulnogram',
        csrfToken: req.csrfToken()
    });
});

// Login process
public.post('/login', csrfProtection, function (req, res, next) {
    passport.authenticate('local', {
        successRedirect: req.session.returnTo || '/home',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// Logout form
public.get('/logout', function (req, res, next) {
    req.logout(function(err){
        if(err) {
            return next(err);
        }
        req.session.returnTo = null;
        req.flash('success', 'You are logged out');
        res.redirect('/users/login');
    });
});


//List users
protected.get('/list', function (req, res) {
    if (req.isAuthenticated()) {
        User.find({}, [], {
            sort: {
                _id: 1
            }
        }, function (err, users) {
            if (err) {
                res.status(500).send('Error');
            } else {
                res.render('users/index', {
                    users: users,
                    page: 'users'
                });
            }
        });
    } else {

    }
});

protected.get('/list/json', function (req, res) {
    if (req.isAuthenticated()) {
        User.find(teammateQuery(req.user), ['username','name','emoji'], {
            sort: {
                username: 1
            }
        }, function (err, users) {
            if (err) {
                res.status(500).send('Error');
            } else {
                res.json({
                default: req.user.username,
                enum: users.map(function(u) { return u.username;}),
                options: {enum_titles: users.map(function(u){return u.name})
                }});
            }
        });
    } else {

    }
});
protected.get('/list/css', function (req, res) {
    if (req.isAuthenticated()) {
        User.find(teammateQuery(req.user), ['username','name','emoji'], {
            sort: {
                username: 1
            }
        }, function (err, users) {
            if (err) {
                res.status(500).send('Error');
            } else {
                res.setHeader('Content-Type', 'text/css');
                for(u of users) {
                    res.write('input[value="'+u.username+'"] + .lbl:before, #vgListTable span[title="'+u.username+'"]:before, .vguser[title="'+u.username+'"]:before {content: "' + u.emoji + ' ";}\n');
                }
                res.end();
            }
        });
    } else {

    }
});
// ---- CNA login profiles (hybrid): metadata only, the API key is NEVER stored ----
// Endpoints come from instance settings (item 7), falling back to the built-ins.
const instanceSettings = require('../lib/instance-settings');
function cnaServices() {
    return (conf.cveServices && conf.cveServices.length) ? conf.cveServices : instanceSettings.DEFAULT_CVE_SERVICES;
}
function cnaServiceUrls() {
    return cnaServices().map(function (s) { return s.url; });
}

// Manage saved CNA logins.
protected.get('/cna', csrfProtection, function (req, res) {
    res.render('users/cna', {
        title: 'CNA logins',
        profiles: req.user.cnaProfiles || [],
        portalUrls: cnaServices(),
        page: 'users',
        csrfToken: req.csrfToken()
    });
});

// JSON list for the CVE Services login-box picker (no secret to return).
protected.get('/cna/json', function (req, res) {
    res.json({
        profiles: (req.user.cnaProfiles || []).map(function (p) {
            return { id: p.id, label: p.label, org: p.org, user: p.user, serviceUrl: p.serviceUrl };
        }),
        services: cnaServices()
    });
});

protected.post('/cna', csrfProtection, async function (req, res) {
    try {
        var org = (req.body.org || '').trim().substring(0, 64);
        var user = (req.body.user || '').trim().substring(0, 128);
        var label = (req.body.label || '').trim().substring(0, 60);
        var serviceUrl = (req.body.serviceUrl || '').trim();
        if (!org || !user) {
            req.flash('error', 'Org short name and CVE user are required.');
            return res.redirect('/users/cna');
        }
        var urls = cnaServiceUrls();
        if (urls.indexOf(serviceUrl) < 0) {
            serviceUrl = urls[0];
        }
        if (!label) {
            label = org + ' / ' + user;
        }
        var profile = {
            id: crypto.randomBytes(8).toString('hex'),
            label: label,
            org: org,
            user: user,
            serviceUrl: serviceUrl
        };
        await User.findOneAndUpdate({ username: req.user.username }, { $push: { cnaProfiles: profile } });
        req.flash('success', 'CNA login "' + label + '" saved.');
        res.redirect('/users/cna');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/users/cna');
    }
});

protected.post('/cna/:id/delete', csrfProtection, async function (req, res) {
    try {
        await User.findOneAndUpdate({ username: req.user.username }, { $pull: { cnaProfiles: { id: req.params.id } } });
        req.flash('success', 'CNA login removed.');
        res.redirect('/users/cna');
    } catch (err) {
        req.flash('error', toErrorMessage(err));
        res.redirect('/users/cna');
    }
});

// Switch the active team used to scope CVE views (and to own newly created CVEs).
// '*' or empty means "all my teams" (the merged view). Stored per-session.
protected.post('/active-team', csrfProtection, function (req, res) {
    var key = (req.body && req.body.team) || '';
    var back = req.get('Referer') || '/';
    var ok = true;
    if (key === '' || key === '*') {
        req.session.activeTeam = null;
    } else if (Array.isArray(req.user.teams) && req.user.teams.some(function (t) { return t.team === key; })) {
        req.session.activeTeam = key;
    } else {
        ok = false;
        req.flash('error', 'You are not a member of that team.');
    }
    // AJAX callers (the team switcher) get JSON; the no-JS <form> fallback redirects.
    var wantsJson = req.xhr || (req.get('Accept') || '').indexOf('application/json') >= 0;
    if (wantsJson) {
        return res.json({ ok: ok, activeTeam: req.session.activeTeam || '' });
    }
    res.redirect(back);
});

// Switch the active CVE Services instance used to scope locally-stored CVEs by
// their `source`. The cve5 portal posts its current endpoint on login/switch and
// an empty value on logout. Stored per-session; empty => unset (behave as before
// tagging). The value only scopes the user's own session/docs, so any well-formed
// http(s) endpoint is accepted (prod, test, or a local instance).
protected.post('/active-source', csrfProtection, function (req, res) {
    var raw = (req.body && req.body.source) || '';
    var back = req.get('Referer') || '/';
    var ok = true;
    if (!raw) {
        req.session.activeSource = null;
    } else {
        var url = normalizePortalUrl(raw);
        if (/^https?:\/\//i.test(url)) {
            req.session.activeSource = url;
        } else {
            ok = false;
        }
    }
    var wantsJson = req.xhr || (req.get('Accept') || '').indexOf('application/json') >= 0;
    if (wantsJson) {
        return res.json({ ok: ok, activeSource: req.session.activeSource || '' });
    }
    res.redirect(back);
});

module.exports = {
    public: public,
    protected: protected
};
