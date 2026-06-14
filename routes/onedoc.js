const express = require('express');
const csurf = require('csurf');
var csrfProtection = csurf();
const textUtil = require('../src/js/edit/util.js');
var jsonpatch = require('json-patch-extended');
var _ = require('lodash');
const docModel = require('../models/doc');
const querymw = require('../lib/querymw');
const docAccess = require('../lib/doc-access');
const rbac = require('../lib/rbac');
const Team = require('../models/team');
const workflow = require('../lib/cna-workflow');
const notify = require('../lib/notify');

const {
    check,
    validationResult
} = require('express-validator');

const validator = require('validator');

module.exports = function (Document, opts) {
    var idRegex = new RegExp('^' + opts.idpattern + '$');
    function ensureRouteID(req, res, next) {
        if (idRegex.test(req.params.id)) {
            return next();
        }
        return next('route');
    }

    var checkID = check(opts.jsonidpath)
        .exists()
        .custom((val, {
            req
        }) => {
            if (validator.matches(val, '^' + opts.idpattern + '$')) {
                return true;
            }
            return false;
        })
        .withMessage('Document ID not valid. Expecting ' + opts.idpattern);

    var router = module.router = express.Router();

    // GET docuemnt
    router.get('/:id', ensureRouteID, csrfProtection, [checkID], async function (req, res) {
        var q = {};
        q[opts.idpath] = req.params.id;
        try {
            var doc = await Document.findOne(q);
            if (doc && opts.conf && opts.conf.teamScoped && !docAccess.canAccessDoc(req.user, doc)) {
                res.status(403);
                return res.render('blank', {
                    title: 'Forbidden',
                    message: 'You do not have access to ' + req.params.id + '.'
                });
            }
            if (doc && opts.conf && opts.conf.teamScoped && doc.body && doc.body.CNA_private) {
                doc.body.CNA_private = workflow.normalize(doc.body.CNA_private);
            }
            var ucomments = undefined;
            if (!doc) {
                if (req.params.id != 'new') {
                    req.flash('error', 'ID not found: ' + req.params.id);
                }
            } else {
                ucomments = doc.comments;
            }
            res.locals.renderStartTime = Date.now();
            if (opts.conf.readonly) {
                if (doc) {
                    delete doc._id;
                }
                res.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'none'; font-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");
                res.render((opts.render == 'render' ? 'readonly' : opts.render), {
                    title: req.params.id,
                    doc: doc ? doc : {},
                    textUtil: textUtil,
                    doc_id: req.params.id,
                    csrfToken: req.csrfToken(),
                    renderTemplate: 'default',
                    ucomments: ucomments
                });
            } else {
                var folderList = [];
                if (opts.conf && opts.conf.teamScoped) {
                    try {
                        var folderFilter = docAccess.buildReadFilter(req.user);
                        folderList = (await Document.distinct('folder', folderFilter || {})).filter(Boolean).sort();
                    } catch (e) { folderList = []; }
                }
                var wfStages = [];
                if (opts.conf && opts.conf.teamScoped && doc && doc.team) {
                    try {
                        var wfTeamDoc = await Team.findByKey(doc.team);
                        var stages = workflow.teamStages(wfTeamDoc);
                        if (stages && stages.join(',') !== workflow.DEFAULT_STAGES.join(',')) { wfStages = stages; }
                    } catch (e) { wfStages = []; }
                }
                res.render(opts.edit, {
                    title: req.params.id,
                    opts: opts,
                    doc_id: req.params.id,
                    idpath: opts.jsonidpath,
                    doc: doc,
                    textUtil: textUtil,
                    csrfToken: req.csrfToken(),
                    allowAjax: true,
                    ucomments: ucomments,
                    watching: !!(doc && Array.isArray(doc.watchers) && req.user && doc.watchers.indexOf(req.user.username) >= 0),
                    watchers: (doc && Array.isArray(doc.watchers)) ? doc.watchers : [],
                    workflowLog: (doc && Array.isArray(doc.workflowLog)) ? doc.workflowLog.slice().reverse() : [],
                    folder: (doc && doc.folder) ? doc.folder : '',
                    folders: folderList,
                    wfStages: wfStages
                });
            }
        } catch (err) {
            res.render('blank', {
                title: 'Error',
                message: 'failed. ' + err.message
            });
        }
    });

    if (opts.conf.readonly) {
        return module;
    }

    var existCheck = check(opts.jsonidpath)
        .exists()
        .custom((val, {
            req
        }) => {
            var q = {};
            q[opts.idpath] = val;
            return Document.findOne(q).then((doc) => {
                if (doc) {
                    throw new Error('Document ' + val + ' exists. Save with a different ID or Update the existing one');
                    return false;
                } else {
                    return true;
                }
            });
        });

    var queryMW = querymw(opts.facet);

    // Render a NEW editable document
    router.get('/new', csrfProtection, queryMW, async function (req, res) {
        var doc = null;
        if (req.querymen.query[opts.idpath]) {
            var fq = {};
            fq[opts.idpath] = req.querymen.query[opts.idpath];
            var doc = await Document.findOne(fq);
        }
        if (doc) {
            res.redirect(req.querymen.query[opts.idpath]);
        } else {
            var doc = {};
            for (var a in req.querymen.query) {
                _.set(doc, a, req.querymen.query[a]);
            };
            //console.log(JSON.stringify(req.querymen.query));
            res.render(opts.edit, {
                title: 'New',
                doc: doc,
                opts: opts,
                idpath: opts.jsonidpath,
                textUtil: textUtil,
                csrfToken: req.csrfToken(),
                allowAjax: true
            });
        }
    });


    module.addModelHistory = function (model, oldDoc, newDoc) {
        if (oldDoc === null) {
            oldDoc = {
                __v: -1,
                _id: newDoc._id,
                author: newDoc.author,
                updatedAt: newDoc.updatedAt,
                body: {}
            }
        }
        var auditTrail = {
            parent_id: oldDoc._id,
            updatedAt: newDoc.updatedAt,
            author: newDoc.author,
            __v: oldDoc.__v + 1,
            body: {
                old_version: oldDoc.__v,
                old_author: oldDoc.author,
                old_date: oldDoc.updatedAt,
                patch: jsonpatch.compare(oldDoc.body, newDoc.body),
            },
        };
        //todo: replace bulkWrite callback with async insert for better error handling
        if (auditTrail.body.patch.length > 0) {
            model.bulkWrite([{
                insertOne: {
                    document: auditTrail
                }
            }], function (err) {
                if (err) {
                    console.log('Error: saving history ' + err);
                } else {
                }
            });
            return auditTrail;
        } else {
            return null;
        }
    }
    var historyCollectionName = opts.historyCollectionName
        || (opts.conf && opts.conf.historyCollectionName)
        || (opts.schemaName + '_histories');
    var History = docModel(historyCollectionName);
    var addHistory = function(oldDoc, newDoc) {
        return module.addModelHistory(History, oldDoc, newDoc);
    }

    // Creat a new document
    router.post(/\/(new)$/, csrfProtection, [checkID, existCheck], async function (req, res) {
        let errors = validationResult(req).array();
        if (errors.length > 0) {
            var msg = 'Error: ';
            for (var e of errors) {
                msg += e.param + ': ' + e.msg + ' ';
            }
            res.json({
                type: 'err',
                msg: msg
            });
            return;
        }

        let now = new Date();
        let entry = {
            body: req.body,
            author: req.user.username,
            __v: 0,
            createdAt: now,
            updatedAt: now
        };
        if (opts.conf && opts.conf.teamScoped) {
            if (!rbac.can(req.user, rbac.CAPABILITIES.CVE_CREATE)) {
                res.json({ type: 'err', msg: 'You do not have permission to create CVEs.' });
                return;
            }
            var pteam = docAccess.resolveOwningTeam(req.user, req.session && req.session.activeTeam);
            entry.owner = req.user.username;
            entry.team = pteam;
            entry.visibility = pteam ? 'team' : 'private';
            entry.sharedWith = [];
        }
        try {
            var inserted = await Document.insertOne(entry);
            var doc = Object.assign({}, entry, { _id: inserted.insertedId });
            addHistory(null, doc);
            res.json({
                type: 'go',
                to: _.get(doc, opts.idpath)
            });
        } catch (err) {
            res.json({
                type: 'err',
                msg: 'Error ' + err
            });
        }
        return;
    });

    // Update or insert existing Document ID 
    router.post('/:id', ensureRouteID, csrfProtection, [checkID], async function (req, res) {
        let errors = validationResult(req).array();
        if (errors.length > 0) {
            var msg = 'Error: ';
            for (var e of errors) {
                msg += e.param + ': ' + e.msg + ' ';
            }
            res.json({
                type: 'err',
                msg: msg
            });
            return;
        }

        //let doc = req.body;
        let inputID = _.get(req, opts.idpath);
        let queryNewID = {};
        let queryOldID = {};
        queryNewID[opts.idpath] = inputID;
        queryOldID[opts.idpath] = req.params.id;
        var renaming = (req.params.id != inputID);
        try {
            var existingDoc = await Document.findOne(queryNewID);
            if (existingDoc) {
                // check Document ID is being renamed.
                if (renaming) {
                    res.json({
                        type: 'err',
                        msg: 'Not saved. Document ' + inputID + ' exists. Save with a different ID or update the existing one.'
                    });
                    return;
                }
            }
            var targetDoc = await Document.findOne(queryOldID);
            if (opts.conf && opts.conf.teamScoped) {
                if (targetDoc) {
                    if (!docAccess.canAccessDoc(req.user, targetDoc) ||
                        !docAccess.canWriteDoc(req.user, targetDoc, rbac.CAPABILITIES.CVE_EDIT)) {
                        res.json({ type: 'err', msg: 'You do not have permission to edit this CVE.' });
                        return;
                    }
                    var wfTeam = targetDoc.team ? await Team.findByKey(targetDoc.team) : null;
                    var fromState = workflow.getState(targetDoc.body && targetDoc.body.CNA_private);
                    var toState = workflow.getState(req.body && req.body.CNA_private);
                    var tv = workflow.validateTransition(req.user, targetDoc, fromState, toState, wfTeam);
                    if (!tv.ok) {
                        res.json({ type: 'err', msg: tv.message });
                        return;
                    }
                } else if (!rbac.can(req.user, rbac.CAPABILITIES.CVE_CREATE)) {
                    res.json({ type: 'err', msg: 'You do not have permission to create CVEs.' });
                    return;
                }
            }
            var d = new Date();
            var newDoc = {
                body: req.body,
                author: req.user.username,
                updatedAt: d
            };
            var setOnInsert = { createdAt: d };
            if (opts.conf && opts.conf.teamScoped && !targetDoc) {
                var newPteam = docAccess.resolveOwningTeam(req.user, req.session && req.session.activeTeam);
                setOnInsert.owner = req.user.username;
                setOnInsert.team = newPteam;
                setOnInsert.visibility = newPteam ? 'team' : 'private';
                setOnInsert.sharedWith = [];
            }
            var updateResult = await Document.findOneAndUpdate(
                queryOldID,
                {
                    "$set": newDoc,
                    "$inc": {
                        __v: 1
                    },
                    "$setOnInsert": setOnInsert
                }, {
                    upsert: true,
                    returnDocument: 'before'
                });
            var oldDoc = updateResult || null;
            if (oldDoc) {
                addHistory(oldDoc, newDoc);
            } else {
                var insertedDoc = await Document.findOne(queryNewID);
                addHistory(null, insertedDoc || newDoc);
            }
            if (opts.conf && opts.conf.teamScoped && typeof toState !== 'undefined' && fromState !== toState) {
                try {
                    await Document.updateOne(queryNewID, {
                        $push: {
                            workflowLog: {
                                $each: [{ at: new Date(), by: req.user.username, from: (fromState === undefined ? null : fromState), to: toState }],
                                $slice: -100
                            }
                        }
                    });
                } catch (e) {
                    // workflow audit is non-fatal
                }
                // Best-effort notify watchers/assignees of the stage change. Fire-and-forget
                // (not awaited) and self-contained error handling, so it never blocks/breaks the save.
                notify.sendStageChange(
                    { id: inputID, team: targetDoc.team, watchers: targetDoc.watchers, body: req.body },
                    fromState, toState, req.user, wfTeam
                ).catch(function (e) { console.log('notify stage change failed: ' + (e && e.message ? e.message : e)); });
            }
            if (renaming) {
                res.json({
                    type: 'go',
                    to: inputID
                });
            } else {
                res.json({
                    type: 'saved'
                });
            }
        } catch (err) {
            res.json({
                type: 'err',
                msg: 'Error! Document not Updated, ' + err
            });
        }
        return;
    });

    //Delete Document
    router.delete('/:id', ensureRouteID, csrfProtection, async function (req, res) {
        let query = {};
        query[opts.idpath] = req.params.id;
        try {
            if (opts.conf && opts.conf.teamScoped) {
                var doc = await Document.findOne(query);
                if (doc && (!docAccess.canAccessDoc(req.user, doc) ||
                    !docAccess.canWriteDoc(req.user, doc, rbac.CAPABILITIES.CVE_DELETE))) {
                    res.status(403);
                    res.send('You do not have permission to delete this CVE.');
                    return;
                }
            }
            await Document.deleteOne(query);
            res.send('Deleted');
        } catch (err) {
            res.send('Error Deleting');
        }
    });

    // Sharing controls for team-scoped documents.
    router.get('/:id/share', csrfProtection, async function (req, res) {
        if (!(opts.conf && opts.conf.teamScoped)) {
            return res.redirect('/' + opts.schemaName + '/' + req.params.id);
        }
        if (!idRegex.test(req.params.id)) {
            req.flash('error', 'Invalid ID');
            return res.render('blank');
        }
        var q = {};
        q[opts.idpath] = req.params.id;
        var doc = await Document.findOne(q);
        if (!doc) {
            req.flash('error', 'ID not found: ' + req.params.id);
            return res.render('blank');
        }
        if (!docAccess.canAccessDoc(req.user, doc)) {
            res.status(403);
            return res.render('blank', { title: 'Forbidden', message: 'You do not have access to this CVE.' });
        }
        var teams = await Team.find({}, { sort: { key: 1 } });
        res.render('share', {
            title: 'Share ' + req.params.id,
            doc_id: req.params.id,
            doc: doc,
            teams: teams,
            basePath: '/' + opts.schemaName + '/',
            csrfToken: req.csrfToken()
        });
    });

    router.post('/:id/share', csrfProtection, async function (req, res) {
        if (!(opts.conf && opts.conf.teamScoped)) {
            return res.redirect('/' + opts.schemaName + '/' + req.params.id);
        }
        if (!idRegex.test(req.params.id)) {
            req.flash('error', 'Invalid ID');
            return res.render('blank');
        }
        var q = {};
        q[opts.idpath] = req.params.id;
        try {
            var doc = await Document.findOne(q);
            if (!doc) {
                req.flash('error', 'ID not found: ' + req.params.id);
                return res.render('blank');
            }
            if (!docAccess.canWriteDoc(req.user, doc, rbac.CAPABILITIES.CVE_EDIT)) {
                res.status(403);
                return res.render('blank', { title: 'Forbidden', message: 'You do not have permission to change sharing for this CVE.' });
            }
            var allTeams = await Team.find({}, { projection: { key: 1 } });
            var validKeys = allTeams.map(function (t) { return t.key; });
            var team = validKeys.indexOf(req.body.team) >= 0 ? req.body.team : doc.team;
            var visibility = req.body.visibility === 'private' ? 'private' : 'team';
            var sharedWith = req.body.sharedWith;
            if (typeof sharedWith === 'string') { sharedWith = [sharedWith]; }
            if (!Array.isArray(sharedWith)) { sharedWith = []; }
            sharedWith = sharedWith.filter(function (k) { return validKeys.indexOf(k) >= 0 && k !== team; });
            var folder = (req.body.folder || '').trim().substring(0, 80);
            await Document.findOneAndUpdate(q, { $set: { team: team, visibility: visibility, sharedWith: sharedWith, folder: folder } });
            req.flash('success', 'Sharing updated for ' + req.params.id);
            res.redirect('/' + opts.schemaName + '/' + req.params.id);
        } catch (err) {
            req.flash('error', 'Failed to update sharing: ' + err.message);
            res.render('blank');
        }
    });

    // Watch / unwatch a team-scoped document (subscribe to it).
    router.post('/:id/watch', csrfProtection, async function (req, res) {
        if (!(opts.conf && opts.conf.teamScoped) || !idRegex.test(req.params.id)) {
            return res.json({ type: 'err', msg: 'Not supported' });
        }
        var q = {};
        q[opts.idpath] = req.params.id;
        try {
            var doc = await Document.findOne(q);
            if (!doc) {
                return res.json({ type: 'err', msg: 'Not found' });
            }
            if (!docAccess.canAccessDoc(req.user, doc)) {
                res.status(403);
                return res.json({ type: 'err', msg: 'No access' });
            }
            var watchers = Array.isArray(doc.watchers) ? doc.watchers : [];
            var watching;
            if (watchers.indexOf(req.user.username) >= 0) {
                await Document.updateOne(q, { $pull: { watchers: req.user.username } });
                watching = false;
            } else {
                await Document.updateOne(q, { $addToSet: { watchers: req.user.username } });
                watching = true;
            }
            res.json({ type: 'ok', watching: watching });
        } catch (err) {
            res.json({ type: 'err', msg: err.message });
        }
    });

    // Set the folder (organization) of a team-scoped document.
    router.post('/:id/folder', csrfProtection, async function (req, res) {
        if (!(opts.conf && opts.conf.teamScoped) || !idRegex.test(req.params.id)) {
            return res.json({ type: 'err', msg: 'Not supported' });
        }
        var q = {};
        q[opts.idpath] = req.params.id;
        try {
            var doc = await Document.findOne(q);
            if (!doc) {
                return res.json({ type: 'err', msg: 'Not found' });
            }
            if (!docAccess.canWriteDoc(req.user, doc, rbac.CAPABILITIES.CVE_EDIT)) {
                res.status(403);
                return res.json({ type: 'err', msg: 'You do not have permission to organize this CVE.' });
            }
            var folder = (req.body.folder || '').trim().substring(0, 80);
            await Document.updateOne(q, { $set: { folder: folder } });
            res.json({ type: 'ok', folder: folder });
        } catch (err) {
            res.json({ type: 'err', msg: err.message });
        }
    });

    // fetch either logs or comments
    var getSubDocs = async function (subSchema, doc_id) {
        var q = {}
        q[opts.idpath] = doc_id;
        var parentDoc = await Document.findOne(q);
        if (parentDoc) {
            var subq = {
                parent_id: parentDoc._id
            }
            var ret = await subSchema.find(subq, {
                projection: {
                    _id: 0,
                    parent_id: 0
                }
            }).sort({
                updatedAt: -1
            }).toArray();
            return (ret);
        } else {
            return {
                'message': 'No parent document'
            };
        }
    }

    // Get document chage history (JSON patches)
    router.get('/log/:id', ensureRouteID, [checkID], function (req, res) {
        getSubDocs(History, req.params.id).then(r => {
            res.json(r);
        });
    });

    return module;
}
