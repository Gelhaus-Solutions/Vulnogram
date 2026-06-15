const express = require('express');
const csurf = require('csurf');
var csrfProtection = csurf();
const path = require('path');
const os = require('os');
const Busboy = require('busboy');
const fs = require('fs');
var sanitizeFile = require("sanitize-filename");
const docAccess = require('../lib/doc-access');
const rbac = require('../lib/rbac');
const toErrorMessage = require('../lib/error-message');
const rateLimit = require('express-rate-limit');
// input doc, opts

module.exports = function (Document, opts) {
    var router = express.Router();
    var idRegex = new RegExp('^' + opts.idpattern + '$');
    // SAVE a file.

    function checkPattern(req, res, next) {
        if (!idRegex.test(req.params.id)) {
            res.json({
                type: 'err',
                msg: 'Invalid document ID.'
            });
            return;
        }
        return next();
    }

    async function checkDir(req, res, next) {
        if (sanitizeFile(req.params.id) != req.params.id) {
            res.json({
                type: 'err',
                msg: 'Error! document ID contain disallowed characters.'
            });
        } else {
            return next();
        }
    }

    // Source-qualified id match: scope file ops to the active CVE Services instance
    // (req.session.activeSource) so two same-id docs from different instances don't
    // share file metadata. Null source (or non-teamScoped) => unscoped, as before.
    function fileIdQuery(req) {
        var activeSource = (opts.conf && opts.conf.teamScoped && req.session) ? (req.session.activeSource || null) : null;
        return docAccess.sourceQ(opts.idpath, req.params.id, activeSource);
    }

    // Resolve the on-disk path for an attachment, sanitizing the filename and
    // guarding against path traversal. Returns null if the filename is empty
    // after sanitizing or if the resolved path would escape the doc's dir.
    function safeFilePath(id, filename) {
        var base = path.join(opts.conf.files, id, 'file');
        var safe = sanitizeFile(filename || '');
        if (!safe) {
            return null;
        }
        var p = path.normalize(path.join(base, safe));
        return p.startsWith(base) ? p : null;
    }

    // Team/doc-access gate for the attachment routes. For teamScoped sections
    // only: load the doc by id and verify the user may access it (reads) or
    // write to it (mutations, when `capability` is given). Non-teamScoped
    // sections short-circuit so other plugins are unaffected. Without this,
    // any authenticated user could reach another team's files by guessing the
    // document id (which undercuts the team-scoping in doc.js/onedoc.js).
    function checkDocAccess(capability) {
        return async function (req, res, next) {
            if (!(opts.conf && opts.conf.teamScoped)) {
                return next();
            }
            try {
                var doc = await Document.findOne(fileIdQuery(req));
                if (!doc) {
                    res.status(404);
                    return res.json({ type: 'err', msg: 'Document not found.' });
                }
                if (!docAccess.canAccessDoc(req.user, doc)) {
                    res.status(403);
                    return res.json({ type: 'err', msg: 'You do not have access to this document.' });
                }
                if (capability && !docAccess.canWriteDoc(req.user, doc, capability)) {
                    res.status(403);
                    return res.json({ type: 'err', msg: 'You do not have permission for this action.' });
                }
                return next();
            } catch (e) {
                res.status(500);
                return res.json({ type: 'err', msg: toErrorMessage(e) });
            }
        };
    }
    router.post('/:id/file', csrfProtection, checkPattern, checkDir, checkDocAccess(rbac.CAPABILITIES.CVE_EDIT), async function (req, res) {
        var fq = fileIdQuery(req);
        var doc = await Document.findOne(fq);
        if (doc) {
            var fcount = 0;
            var comment;
            // busboy v1.x exports a factory function, not a constructor.
            var busboy = Busboy({
                headers: req.headers
            });
            busboy.on('field', function (fieldname, val, fieldnameTruncated, valTruncated, encoding, mimetype) {
                if (fieldname == 'comment') {
                    comment = val;
                }
            });
            busboy.on('file', async function (fieldname, file, filename, encoding, mimetype) {
                var x = fcount++;
                //console.log('File [' + fieldname + ']: filename: ' + filename + ', encoding: ' + encoding + ', mimetype: ' + mimetype + ' COMMENT: '+ comment);
                //var base = opts.conf.files;
                var collectionDir = opts.conf.files; //path.join(base, req.baseUrl);
                if (!fs.existsSync(collectionDir)) {
                    fs.mkdirSync(collectionDir);
                    //console.log(' Created collection dir' + collectionDir);
                }
                var docDir = path.join(collectionDir, req.params.id);

                if (!fs.existsSync(docDir)) {
                    fs.mkdirSync(docDir);
                    //console.log(' Created Doc dir' + docDir);
                }
                docDir = path.join(docDir, 'file');
                if (!fs.existsSync(docDir)) {
                    fs.mkdirSync(docDir);
                    //console.log(' Created Doc dir' + docDir);
                }

                var safeName = sanitizeFile(filename) || 'attachment';
                var saveTo = path.join(docDir, safeName);
                var pn = path.normalize(saveTo);
                if (pn.startsWith(docDir)) {
                    var w = await file.pipe(fs.createWriteStream(pn));

                    w.on('finish', async function () {
                        var fileq = fileIdQuery(req);
                        fileq['files.name'] = safeName;
                        //console.log('Update query'+ JSON.stringify(fileq));
                        var [ftype, fsubtype] = mimetype ? mimetype.split('/', 2) : ['unknown', 'unknown'];
                        ; var nf = {
                            "name": safeName,
                            "updatedAt": new Date(),
                            "size": w.bytesWritten,
                            "comment": comment,
                            "user": req.user.username,
                            "type": ftype,
                            "subtype": fsubtype
                        };
                        var ret = await Document.findOneAndUpdate(fileq, {
                            '$set': {
                                "files.$": nf
                            }
                        }, {
                            returnDocument: 'after'
                        });
                        if (ret === null) {
                            var ret = await Document.findOneAndUpdate(fq, {
                                $push: {
                                    files: nf
                                }
                            }, {
                                returnDocument: 'after'
                            });
                        }

                        if (x == (fcount - 1)) {
                            if (busboy._done) {
                                res.json({
                                    ok: '1',
                                    //flist: flist
                                })
                            } else {
                                busboy.on('finish', function () {
                                    res.json({
                                        ok: '1',
                                        //flist: flist
                                    })
                                });
                            }
                        }
                    });
                } else {
                    res.json({
                        ok: 0,
                        msg: 'Invalid file path!'
                    });
                }
            });

            /*busboy.on('finish', function () {
                res.json({
                    ok: '1',
                    //flist: flist
                })
            });*/
            req.pipe(busboy);
        } else {
            res.json({
                ok: 0,
                msg: 'Document not found!'
            });
        }
    });

    //GET file contents
    router.get('/:id/file/:filename', checkPattern, checkDir, checkDocAccess(),
        async function (req, res, next) {
            res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'none'");
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Content-Disposition", 'attachment; filename="' + sanitizeFile(req.params.filename) + '"');
            return next();
        },
        express.static(path.join(opts.conf.files))
    );

    // delete file
    router.delete('/:id/file/:filename', csrfProtection, checkPattern, checkDir, checkDocAccess(rbac.CAPABILITIES.CVE_EDIT), async function (req, res) {
        var fq = fileIdQuery(req);
        try {
            var ret = await Document.updateOne(fq, { $pull: { files: { name: req.params.filename } } });
            // Also remove the file from disk so deleted attachments don't linger
            // (and can't be re-served via the public route). Ignore a missing file.
            var diskPath = safeFilePath(req.params.id, req.params.filename);
            if (diskPath) {
                fs.unlink(diskPath, function (err) {
                    if (err && err.code !== 'ENOENT') {
                        console.error('Failed to remove attachment from disk: ' + diskPath, err.message);
                    }
                });
            }
            res.json({ ok: ret.acknowledged ? 1 : 0, n: ret.modifiedCount });
        } catch (e) {
            res.status(500);
            res.json({ ok: 0, msg: toErrorMessage(e) });
        }
    });

    // Toggle the public flag on an attachment. Public files are downloadable
    // without authentication via the publicRouter below. An operator flips this
    // (e.g. once the CVE is published) to expose a PoC, then pastes the returned
    // public URL into the CVE references with the "exploit" tag.
    router.post('/:id/file/:filename/visibility', csrfProtection, checkPattern, checkDir, checkDocAccess(rbac.CAPABILITIES.CVE_EDIT), async function (req, res) {
        try {
            var fq = fileIdQuery(req);
            fq['files.name'] = req.params.filename;
            var doc = await Document.findOne(fq, { projection: { 'files.$': 1 } });
            if (!doc || !doc.files || !doc.files.length) {
                res.status(404);
                return res.json({ ok: 0, msg: 'Attachment not found.' });
            }
            var newVal = !doc.files[0].public;
            await Document.updateOne(fq, { $set: { 'files.$.public': newVal } });
            var url = req.baseUrl + '/' + encodeURIComponent(req.params.id) + '/public/file/' + encodeURIComponent(req.params.filename);
            res.json({ ok: 1, public: newVal, url: url });
        } catch (e) {
            res.status(500);
            res.json({ ok: 0, msg: toErrorMessage(e) });
        }
    });

    // file listing in JSON format
    router.get('/files/:id', checkPattern, checkDir, checkDocAccess(),
        async function (req, res, next) {
            res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'none'");
            return next();
        },

        async function (req, res) {
            var fq = fileIdQuery(req);
            var doc = await Document.findOne(fq, { projection: { files: 1 } });
            res.json(doc ? doc.files : []);
        });

    // Directory listing
    router.get('/:id/file/', checkPattern, checkDir, checkDocAccess(), function (req, res) {
        fs.readdir(path.join(opts.conf.files, req.params.id, '/file/'), function (err, items) {
            res.render(opts.list, {
                title: req.params.id + ' files',
                docs: items ? items.map(x => {
                    return ({
                        'File': x,
                        'Filetype': x.substr(x.lastIndexOf('.') + 1)
                    })
                }) : [],
                columns: ['File', 'Filetype'],
                subtitle: 'Attachments for ' + req.params.id
            });
        });
    });

    // --- Public (unauthenticated) download router ---------------------------
    // Mounted in app.js BEFORE ensureAuthenticated. Serves an attachment only
    // when its files[] entry is explicitly flagged public:true in the DB, so
    // disk presence alone is never enough. Force-download + nosniff + strict CSP
    // neutralize stored-XSS from user-uploaded HTML/SVG/JS served from our origin.
    var publicRouter = express.Router();
    var publicLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, validate: { trustProxy: false } });
    publicRouter.get('/:id/public/file/:filename', publicLimiter, checkPattern, checkDir, async function (req, res) {
        try {
            // No session here (unauthenticated): match by id only, unscoped by
            // source. If the same id exists from multiple instances, first wins.
            var doc = await Document.findOne(docAccess.sourceQ(opts.idpath, req.params.id, null), { projection: { files: 1 } });
            var entry = (doc && Array.isArray(doc.files))
                ? doc.files.find(function (f) { return f && f.name === req.params.filename && f.public === true; })
                : null;
            var diskPath = safeFilePath(req.params.id, req.params.filename);
            if (!entry || !diskPath || !fs.existsSync(diskPath)) {
                res.status(404);
                return res.json({ type: 'err', msg: 'Not found.' });
            }
            res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'none'");
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Content-Disposition", 'attachment; filename="' + sanitizeFile(req.params.filename) + '"');
            return res.sendFile(path.resolve(diskPath));
        } catch (e) {
            res.status(500);
            return res.json({ type: 'err', msg: toErrorMessage(e) });
        }
    });

    return { router: router, publicRouter: publicRouter };
}
