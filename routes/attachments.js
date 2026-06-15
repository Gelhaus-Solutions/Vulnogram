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
        if (!doc) {
            return res.json({ ok: 0, msg: 'Document not found!' });
        }
        var comment;
        var pending = [];   // one promise per file: write to disk, then record metadata
        var hadError = false;
        // busboy v1.x exports a factory (not a constructor) and emits 'file' with
        // an info object { filename, encoding, mimeType } as the 3rd argument.
        var busboy = Busboy({ headers: req.headers });
        busboy.on('field', function (fieldname, val) {
            if (fieldname == 'comment') {
                comment = val;
            }
        });
        busboy.on('file', function (fieldname, file, info) {
            var filename = info && info.filename;
            var mimetype = info && info.mimeType;
            if (!filename) {
                file.resume(); // drain & skip parts without a filename
                return;
            }
            pending.push((async function () {
                var collectionDir = opts.conf.files;
                if (!fs.existsSync(collectionDir)) { fs.mkdirSync(collectionDir); }
                var docDir = path.join(collectionDir, req.params.id);
                if (!fs.existsSync(docDir)) { fs.mkdirSync(docDir); }
                docDir = path.join(docDir, 'file');
                if (!fs.existsSync(docDir)) { fs.mkdirSync(docDir); }

                var safeName = cleanFilename(filename);
                var pn = path.normalize(path.join(docDir, safeName));
                if (!pn.startsWith(docDir)) {
                    file.resume();
                    hadError = true;
                    return;
                }
                var w = fs.createWriteStream(pn);
                await new Promise(function (resolve, reject) {
                    file.on('error', reject);
                    w.on('error', reject);
                    w.on('finish', resolve);
                    file.pipe(w);
                });
                var [ftype, fsubtype] = mimetype ? mimetype.split('/', 2) : ['unknown', 'unknown'];
                var nf = {
                    "name": safeName,
                    "updatedAt": new Date(),
                    "size": w.bytesWritten,
                    "comment": comment,
                    "user": req.user.username,
                    "type": ftype,
                    "subtype": fsubtype
                };
                // Update an existing same-named entry in place, else append.
                var fileq = fileIdQuery(req);
                fileq['files.name'] = safeName;
                var ret = await Document.findOneAndUpdate(fileq, { '$set': { "files.$": nf } }, { returnDocument: 'after' });
                if (ret === null) {
                    await Document.findOneAndUpdate(fq, { $push: { files: nf } }, { returnDocument: 'after' });
                }
            })().catch(function (e) {
                hadError = true;
                console.error('Attachment upload failed: ' + (e && e.message));
            }));
        });
        busboy.on('close', async function () {
            await Promise.all(pending);
            if (hadError) {
                res.status(500);
                return res.json({ ok: 0, msg: 'One or more files failed to upload.' });
            }
            res.json({ ok: '1' });
        });
        req.pipe(busboy);
    });

    // GET the attachment overview page (any file the viewer can access). The bytes
    // are served from the /raw sub-route below; this shows details + a preview.
    router.get('/:id/file/:filename', checkPattern, checkDir, checkDocAccess(), async function (req, res) {
        try {
            var doc = await Document.findOne(fileIdQuery(req), { projection: { files: 1 } });
            var entry = findEntryByName(doc, req.params.filename);
            var base = req.baseUrl + '/' + encodeURIComponent(req.params.id) + '/file/' + encodeURIComponent(req.params.filename);
            return renderLanding(req, res, entry, base);
        } catch (e) {
            res.status(500);
            return res.json({ type: 'err', msg: toErrorMessage(e) });
        }
    });

    // GET the raw bytes (inline preview for safe types; ?download=1 forces download).
    router.get('/:id/file/:filename/raw', checkPattern, checkDir, checkDocAccess(), async function (req, res) {
        try {
            var doc = await Document.findOne(fileIdQuery(req), { projection: { files: 1 } });
            var entry = findEntryByName(doc, req.params.filename);
            return serveRaw(req, res, entry);
        } catch (e) {
            res.status(500);
            return res.json({ type: 'err', msg: toErrorMessage(e) });
        }
    });

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

    // --- Shared attachment overview / raw-byte helpers ----------------------
    function findEntryByName(doc, filename) {
        return (doc && Array.isArray(doc.files))
            ? doc.files.find(function (f) { return f && f.name === filename; })
            : null;
    }
    function findPublicEntry(doc, filename) {
        var e = findEntryByName(doc, filename);
        return (e && e.public === true) ? e : null;
    }

    function humanSize(n) {
        if (typeof n !== 'number' || !isFinite(n) || n < 0) { return ''; }
        if (n < 1024) { return n + ' B'; }
        var units = ['KB', 'MB', 'GB', 'TB'];
        var i = -1;
        do { n = n / 1024; i++; } while (n >= 1024 && i < units.length - 1);
        return n.toFixed(1) + ' ' + units[i];
    }

    // What the overview page renders inline for a given entry.
    function previewKindFor(entry) {
        var t = entry.type;
        var s = (entry.subtype || '').toLowerCase();
        var raster = { png: 1, jpeg: 1, jpg: 1, gif: 1, webp: 1, bmp: 1, 'x-icon': 1, 'vnd.microsoft.icon': 1 };
        if (t === 'image' && raster[s]) { return 'image'; }
        if (t === 'application' && s === 'pdf') { return 'pdf'; }
        if (t === 'text') { return 'text'; }
        if (t === 'application' && (s === 'json' || s === 'xml' || s === 'x-yaml' || s === 'yaml' || s === 'csv' || s === 'javascript' || s === 'x-sh')) { return 'text'; }
        return 'none';
    }

    // Content-Type for serving bytes INLINE. Returns null for types unsafe to
    // render in our origin (html, svg, unknown) -> caller forces a download.
    // Textual types are pinned to text/plain so an uploaded .html/.svg can never
    // be parsed or executed by the browser.
    function inlineContentType(entry) {
        var t = entry.type;
        var s = (entry.subtype || '').toLowerCase();
        var raster = { png: 'image/png', jpeg: 'image/jpeg', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', 'x-icon': 'image/x-icon', 'vnd.microsoft.icon': 'image/x-icon' };
        if (t === 'image' && raster[s]) { return raster[s]; }
        if (t === 'application' && s === 'pdf') { return 'application/pdf'; }
        if (previewKindFor(entry) === 'text') { return 'text/plain; charset=utf-8'; }
        return null;
    }

    // Render the attachment overview page (details + inline preview when supported).
    // `basePath` is this attachment's URL; the bytes live at `basePath + '/raw'`.
    // Shared by the authenticated and public routes. The page is TRUSTED HTML (all
    // values pug-escaped); untrusted bytes are isolated at /raw with strict headers.
    function renderLanding(req, res, entry, basePath) {
        var diskPath = safeFilePath(req.params.id, req.params.filename);
        if (!entry || !diskPath || !fs.existsSync(diskPath)) {
            res.status(404);
            return res.render('publicfile', { notFound: true, title: 'Attachment not available' });
        }
        var kind = previewKindFor(entry);
        var textContent = null;
        if (kind === 'text') {
            var size = typeof entry.size === 'number' ? entry.size : fs.statSync(diskPath).size;
            if (size <= 512 * 1024) {
                try { textContent = fs.readFileSync(diskPath, 'utf8'); } catch (e) { kind = 'none'; }
            } else {
                kind = 'toobig';
            }
        }
        return res.render('publicfile', {
            title: entry.name,
            cveId: req.params.id,
            file: entry,
            isPublic: entry.public === true,
            // The shareable, login-free URL (always the /public/ path), surfaced on
            // the page so operators don't accidentally share the authenticated /file/
            // URL from the address bar (which 302s to login for logged-out viewers).
            publicUrl: entry.public === true
                ? (req.baseUrl + '/' + encodeURIComponent(req.params.id) + '/public/file/' + encodeURIComponent(entry.name))
                : null,
            sizeStr: humanSize(entry.size),
            updatedStr: entry.updatedAt ? new Date(entry.updatedAt).toUTCString() : '',
            kind: kind,
            textContent: textContent,
            rawUrl: basePath + '/raw',
            downloadUrl: basePath + '/raw?download=1'
        });
    }

    // Serve the raw bytes. Inline preview for a safelist of inert types; otherwise
    // (or with ?download=1) force a download. nosniff + an explicit Content-Type
    // keep user-uploaded content from being sniffed or executed in our origin.
    function serveRaw(req, res, entry) {
        var diskPath = safeFilePath(req.params.id, req.params.filename);
        if (!entry || !diskPath || !fs.existsSync(diskPath)) {
            res.status(404);
            return res.json({ type: 'err', msg: 'Not found.' });
        }
        var safe = sanitizeFile(req.params.filename);
        res.setHeader("X-Content-Type-Options", "nosniff");
        var wantsDownload = req.query.download === '1' || req.query.download === 'true';
        var inlineType = wantsDownload ? null : inlineContentType(entry);
        if (inlineType) {
            // Pre-set Content-Type so res.sendFile won't override it from the file
            // extension; inline disposition lets the browser preview it.
            res.setHeader("Content-Type", inlineType);
            res.setHeader("Content-Disposition", 'inline; filename="' + safe + '"');
            return res.sendFile(path.resolve(diskPath));
        }
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Disposition", 'attachment; filename="' + safe + '"');
        return res.sendFile(path.resolve(diskPath));
    }

    // --- Public (unauthenticated) attachment access -------------------------
    // Mounted in app.js BEFORE ensureAuthenticated. A file is reachable here only
    // when its files[] entry is explicitly flagged public:true in the DB (disk
    // presence alone is never enough).
    var publicRouter = express.Router();
    var publicLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, validate: { trustProxy: false } });

    publicRouter.get('/:id/public/file/:filename', publicLimiter, checkPattern, checkDir, async function (req, res) {
        try {
            // No session here (unauthenticated): match by id only, unscoped by source.
            var doc = await Document.findOne(docAccess.sourceQ(opts.idpath, req.params.id, null), { projection: { files: 1 } });
            var entry = findPublicEntry(doc, req.params.filename);
            var base = req.baseUrl + '/' + encodeURIComponent(req.params.id) + '/public/file/' + encodeURIComponent(req.params.filename);
            return renderLanding(req, res, entry, base);
        } catch (e) {
            res.status(500);
            return res.json({ type: 'err', msg: toErrorMessage(e) });
        }
    });

    publicRouter.get('/:id/public/file/:filename/raw', publicLimiter, checkPattern, checkDir, async function (req, res) {
        try {
            var doc = await Document.findOne(docAccess.sourceQ(opts.idpath, req.params.id, null), { projection: { files: 1 } });
            var entry = findPublicEntry(doc, req.params.filename);
            return serveRaw(req, res, entry);
        } catch (e) {
            res.status(500);
            return res.json({ type: 'err', msg: toErrorMessage(e) });
        }
    });

    return { router: router, publicRouter: publicRouter };
}
