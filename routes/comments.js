const express = require('express');
const csrfProtection = require('../lib/csrf');
const crypto = require('crypto');
const { sanitizeRichHtml } = require('../lib/html-sanitize');
const docAccess = require('../lib/doc-access');
const rbac = require('../lib/rbac');
const toErrorMessage = require('../lib/error-message');

var random_slug = function () {
    return crypto.randomBytes(13).toString('base64').replace(/[\+\/\=]/g, '-');
}

/*
* if integrated with email, it shows emails with the same ID in the subject line

var matchingEmail = async function (doc_id) {
    try{
    return await Document.db.collection('mails').find({
        '$text': {
            '$search': '"' + doc_id + '"'
        }
    }, {
        'author': 1,
        'subject': 1,
        'hypertext': 1,
       // 'html': 1,
        'createdAt': 1,
        _id: 1
    }).toArray();
    } catch(e) {
        return [];
    }
};*/


// input doc, opts
module.exports = function (Document, opts) {

    // Scope comment writes to the active CVE Services instance so a comment lands on
    // the right copy when the same CVE ID exists on multiple instances.
    function commentIdQuery(doc_id, req) {
        var activeSource = (opts.conf && opts.conf.teamScoped && req && req.session) ? (req.session.activeSource || null) : null;
        return docAccess.sourceQ(opts.idpath, doc_id, activeSource);
    }

    var unifiedComments = async function (doc_id, comments) {
        var emails = null;
        //var emails = await matchingEmail(doc_id);
        //console.log('GOT emails' + emails);
        var u = [];
        if (emails) {
            u = u.concat(emails);
        }
        if (comments) {
            u = u.concat(comments);
        }
        u.sort(function (a, b) { return b.createdAt - a.createdAt; });
        return u;
    }

    var addComment = async function (doc_id, username, text, parent_slug, req) {
        try {

            //var posted = new Date();
            var slug = random_slug();
            var q = commentIdQuery(doc_id, req);
            //console.log('Commenting on ' + doc_id + ' q=' + JSON.stringify(q))
            var dt = new Date();
            var ret = await Document.findOneAndUpdate(
                q, {
                $push: {
                    comments: {
                        $each: [{
                            createdAt: dt,
                            updatedAt: dt,
                            author: username,
                            slug: slug,
                            hypertext: sanitizeRichHtml(text),
                        }], $position: 0
                    }
                }
            }, { returnDocument: 'after' });

            return ({
                ok: 1,
                ret: await unifiedComments(doc_id, ret ? ret.comments : []),
            });
        } catch (e) {
            return ({
                msg: toErrorMessage(e)
            });
        }
    }

    var updateComment = async function (doc_id, username, text, slug, date, req) {
        try {
            var q = commentIdQuery(doc_id, req);
            q['comments.slug'] = slug;
            q['comments.author'] = username;
            var ret = await Document.findOneAndUpdate(q, {
                '$set': {
                    "comments.$.hypertext": sanitizeRichHtml(text),
                    "comments.$.updatedAt": date
                }
            }, {
                returnDocument: 'after'
            });
            return ({
                ok: 1,
                ret: await unifiedComments(doc_id, ret ? ret.comments : [])
            });
        } catch (e) {
            return ({
                msg: toErrorMessage(e)
            });
        }
    }
    var idRegex = new RegExp('^' + opts.idpattern + '$');

    // Validate the id, load the doc, and enforce team read/write access before
    // commenting. Rejects non-string ids/slugs (which would otherwise allow NoSQL
    // operator injection via req.body) and cross-team access (IDOR).
    async function authorizeComment(req, res) {
        var id = req.body.id;
        if (typeof id !== 'string' || !idRegex.test(id)) {
            res.json({ msg: 'Invalid document ID.' });
            return null;
        }
        if (typeof req.body.text !== 'string' || !req.body.text.trim()) {
            res.json({ msg: 'Comment text is required.' });
            return null;
        }
        if (req.body.slug !== undefined && typeof req.body.slug !== 'string') {
            res.json({ msg: 'Invalid comment reference.' });
            return null;
        }
        var doc = await Document.findOne(commentIdQuery(id, req));
        if (!doc) {
            res.json({ msg: 'Document not found.' });
            return null;
        }
        if (opts.conf && opts.conf.teamScoped) {
            if (!docAccess.canAccessDoc(req.user, doc) ||
                !docAccess.canWriteDoc(req.user, doc, rbac.CAPABILITIES.CVE_EDIT)) {
                res.status(403);
                res.json({ msg: 'You do not have permission to comment on this document.' });
                return null;
            }
        }
        return doc;
    }

    var router = express.Router();
    router.post('/comment', csrfProtection, async function (req, res) {
        try {
            var doc = await authorizeComment(req, res);
            if (!doc) { return; }
            var r;
            if (req.body.slug) {
                r = await updateComment(req.body.id, req.user.username, req.body.text, req.body.slug, new Date(), req);
            } else {
                r = await addComment(req.body.id, req.user.username, req.body.text, undefined, req);
            }
            res.json(r);
        } catch (e) {
            res.json({ msg: toErrorMessage(e) });
        }
    });
    return router;
}
