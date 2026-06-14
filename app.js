// Copyright (c) 2017 Chandan B N. All rights reserved.

const express = require('express');
const path = require('path');
const http = require('http');
const flash = require('connect-flash');
const https = require('https');
const pug = require('pug');
const session = require('express-session');
// connect-mongo v6 is ESM-first; the CJS build exposes the store as the default export.
const MongoStore = require('connect-mongo').default;

const passport = require('passport');
const crypto = require('crypto');
const fs = require('fs');
const compress = require('compression');

if (process.cwd() !== __dirname) {
    try {
        process.chdir(__dirname);
    } catch (err) {
        console.error('Failed to set working directory to app root:', err.message);
        process.exit(1);
    }
}

const dotenv = require('dotenv').config()
if (dotenv.error) {
    console.log(".env was not loaded.");
}

const conf = require('./config/conf');
const optSet = require('./models/set');
const { sanitizeRichHtml } = require('./lib/html-sanitize');
const mongo = require('./lib/mongo');
const rbac = require('./lib/rbac');
const instanceSettings = require('./lib/instance-settings');
const teamModel = require('./models/team');

if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = "production";
}

let db = null;

const app = express();

var rateLimit = require('express-rate-limit');
var limiter = rateLimit({
  windowMs: 1*60*1000, // 1 minute
  max: 200
});
// apply rate limiter to all requests
app.use(limiter);

app.disable('x-powered-by');

// enable compression
app.use(compress());

app.set('env', 'production');
// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// make conf available for pug
app.locals.conf = conf;
app.locals.pugLib = pug;
app.locals.sanitizeRichHtml = sanitizeRichHtml;

// parse urlencoded forms
app.use(express.urlencoded({
    extended: true
}));

// parse application/json
app.use(express.json({limit:'16mb'}));

// serve files under public freely
app.use(express.static('public'));

// Express Session middleware
const useSecureCookie = process.env.VULNOGRAM_SECURE_COOKIE === 'true' || !!conf.httpsOptions;

// Trust proxy configuration for running behind a reverse proxy / load balancer.
// Set TRUST_PROXY to one of:
//   true | false | a hop count (e.g. 1) | an IP/subnet or comma list (e.g. "loopback, 10.0.0.0/8")
// If unset, the immediate proxy is trusted (1 hop) when secure cookies are enabled.
function resolveTrustProxy() {
    var raw = process.env.TRUST_PROXY;
    if (raw === undefined || raw.trim() === '') {
        return process.env.VULNOGRAM_SECURE_COOKIE === 'true' ? 1 : undefined;
    }
    var trimmed = raw.trim();
    if (trimmed.toLowerCase() === 'true') {
        return true;
    }
    if (trimmed.toLowerCase() === 'false') {
        return false;
    }
    if (/^\d+$/.test(trimmed)) {
        return Number(trimmed);
    }
    return trimmed;
}
const trustProxy = resolveTrustProxy();
if (trustProxy !== undefined) {
    app.set('trust proxy', trustProxy);
}
// Stable session secret so sessions survive restarts and multiple workers.
// Prefer SESSION_SECRET from the environment; otherwise persist a generated one.
function resolveSessionSecret() {
    if (process.env.SESSION_SECRET) {
        return process.env.SESSION_SECRET;
    }
    const secretPath = path.join(__dirname, 'config', '.session-secret');
    try {
        const existing = fs.readFileSync(secretPath, 'utf8').trim();
        if (existing) {
            return existing;
        }
    } catch (err) {
        // secret file not created yet
    }
    const generated = crypto.randomBytes(64).toString('hex');
    try {
        fs.writeFileSync(secretPath, generated, { mode: 0o600 });
    } catch (err) {
        console.warn('Could not persist session secret (' + err.message + '); set SESSION_SECRET to keep sessions across restarts.');
    }
    return generated;
}

function sessionDbName(uri) {
    try {
        const fromPath = (new URL(uri).pathname || '').replace(/^\//, '');
        return fromPath || 'vulnogram';
    } catch (err) {
        return 'vulnogram';
    }
}

// Sessions persist in MongoDB (connect-mongo) instead of memory, so a restart no
// longer logs everyone out and the app can run multiple processes.
const sessionMiddleware = session({
    secret: resolveSessionSecret(),
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl: conf.database,
        dbName: sessionDbName(conf.database),
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60
    }),
    cookie: {
      httpOnly: true,
      secure: useSecureCookie
    }
});
app.use(sessionMiddleware);

// Passport config
require('./config/passport')(passport);

app.use(passport.initialize());
app.use(passport.session());

// Express Messages Middleware
// This shows error messages on the client
app.use(require('connect-flash')());
app.use(function (req, res, next) {
    res.locals.user = req.user || null;
    res.locals.startTime = Date.now();
    res.locals.messages = require('express-messages')(req, res);
    // Capability check available to all templates so the UI can hide disallowed actions.
    res.locals.can = function (capability, context) {
        return req.user ? rbac.can(req.user, capability, context) : false;
    };
    next();
});

// add this to route for authenticating before certain requests.
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        res.redirect('/users/login')
    }
}

function ensureConnected(req, res, next) {
    if (mongo.isConnected()) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        req.flash('error', 'Database error! Ensure mongod is up and check the settings on the server.')
        res.status(500);
        res.render('splash', {
            title: 'Vulnogram'
        });
    }
}

app.use(ensureConnected);

//delete return redirect path
app.use(function (req, res, next) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader("Access-Control-Allow-Origin", "*");// XXX investigate
    res.setHeader("Access-Control-Request-Headers", "cve-api-cna,cve-api-secret,cve-api-submitter");

    if (req.path != '/users/login' && req.session.returnTo) {
        delete req.session.returnTo
    }
    next()
})

// Resolve the user's team keys to display names for the team switcher, and expose
// the currently selected active team. Team names are cached briefly to avoid a DB
// query on every request (the teams collection is small).
var teamNameCache = { at: 0, map: {} };
async function getTeamNameMap() {
    var now = Date.now();
    if (now - teamNameCache.at < 60000 && Object.keys(teamNameCache.map).length) {
        return teamNameCache.map;
    }
    var teams = await teamModel.find({}, { projection: { key: 1, name: 1 } });
    var map = {};
    teams.forEach(function (t) { map[t.key] = t.name || t.key; });
    teamNameCache = { at: now, map: map };
    return map;
}
app.use(async function (req, res, next) {
    res.locals.userTeams = [];
    res.locals.activeTeam = (req.session && req.session.activeTeam) || '';
    res.locals.teamNames = {};
    try {
        if (req.user) {
            var map = await getTeamNameMap();
            // Full key->name map so owning-team badges resolve for ANY team a doc
            // might belong to (incl. shared / instance-wide-visible docs), not just
            // the viewer's own memberships.
            res.locals.teamNames = map;
            if (Array.isArray(req.user.teams) && req.user.teams.length) {
                res.locals.userTeams = req.user.teams
                    .map(function (t) { return { key: t.team, name: map[t.team] || t.team }; })
                    .filter(function (t) { return t.key; });
            }
        }
    } catch (e) {
        // On any lookup failure, leave the switcher empty rather than break the page.
    }
    next();
})

async function bootstrap() {
    try {
        db = await mongo.connect(conf.database);
        console.log('Connected to MongoDB');
        try {
            await rbac.loadRoles();
        } catch (roleErr) {
            console.error('Failed to load RBAC roles:', roleErr.message);
        }
        try {
            await instanceSettings.apply();
        } catch (settingsErr) {
            console.error('Failed to apply instance settings:', settingsErr.message);
        }
    } catch (err) {
        console.error(err.message);
        console.error('Check mongodb connection URL configuration. Ensure Mongodb server is running!');
        process.exit(1);
    }
    // set up routes
    let users = require('./routes/users');
    app.use('/users', users.public);
    app.use('/users', ensureAuthenticated, users.protected);

    let admin = require('./routes/admin');
    app.use('/admin', ensureAuthenticated, admin);

    let templates = require('./routes/templates');
    app.use('/templates', ensureAuthenticated, templates);

    let docs = require('./routes/doc');

    app.locals.confOpts = {};

    var sections = require('./models/sections.js')();

    for (var section of sections) {
        var s = optSet(section, ['default', 'custom']);
        //var s = conf.sections[section];
        if (s.facet && s.facet.ID) {
            app.locals.confOpts[section] = s;
            let r = docs(section, app.locals.confOpts[section]);
            // Public, unauthenticated attachment downloads must be reachable
            // without login, so mount the public router BEFORE ensureAuthenticated.
            // Unmatched paths fall through to the authenticated router below.
            if (r.publicRouter) {
                app.use('/' + section, r.publicRouter);
            }
            app.use('/' + section, ensureAuthenticated, r.router);
        }
    }

    app.use('/home/stats', ensureAuthenticated, async function (req, res, next) {
        var sections = [];
        for (var section of conf.sections) {
            var s = {};
            var sectionOpts = app.locals.confOpts[section];
            var collectionName = sectionOpts && sectionOpts.conf && sectionOpts.conf.collectionName
                ? sectionOpts.conf.collectionName
                : section;
            try {
                s = await db.collection(collectionName).stats();
            } catch (e) {
            }

            sections.push({
                name: section,
                items: s.count,
                size: s.size,
                avgSize: s.avgObjSize
            });
        }
        res.render('list',
            {
                docs: sections,
                columns: ['name', 'items', 'size', 'avgSize'],
                fields: {
                    'name': {
                        className: 'icn'
                    }
                }
            })
    });

    app.use(function (req, res, next) {
        res.locals.confOpts = app.locals.confOpts;
        next();
    });

    if (conf.customRoutes) {
        for (var r of conf.customRoutes) {
            app.use(r.path, require(r.route));
        }
    }

    app.get('/', function (req, res, next) {
        res.redirect(conf.homepage ? conf.homepage : '/home');
    });

    const realtimeEnabled = !conf.realtime || conf.realtime.enabled !== false;
    const server = conf.httpsOptions ? https.createServer(conf.httpsOptions, app) : http.createServer(app);

    if (realtimeEnabled) {
        const { Server } = require('socket.io');
        const io = new Server(server, {
            maxHttpBufferSize: conf.realtime && conf.realtime.maxPatchBytes ? conf.realtime.maxPatchBytes * 2 : 1e6
        });
        require('./lib/realtime')(io, {
            sessionMiddleware: sessionMiddleware,
            passport: passport,
            conf: conf,
            confOpts: app.locals.confOpts
        });
    }

    server.listen(conf.serverPort, conf.serverHost, function () {
        console.log('Server started at ' + (conf.httpsOptions ? 'https://' : 'http://') + conf.serverHost + ':' + conf.serverPort);
    });

    // Keep the local NVD copy (the read-only "nvd" section) fresh from within
    // the app, so no external cron job is needed. Controlled by conf.nvdSync.
    try {
        require('./lib/nvd-scheduler').start();
    } catch (err) {
        console.error('NVD sync scheduler failed to start:', err.message);
    }

    // Warm the NVD stats cache in the background if missing/stale, so /nvd is fast
    // even when sync is disabled. Non-blocking.
    try {
        require('./lib/nvd-stats').refreshIfStale(24 * 60 * 60 * 1000).catch(function () {});
    } catch (err) {
        console.error('NVD stats warm-up failed:', err.message);
    }
}

bootstrap();
