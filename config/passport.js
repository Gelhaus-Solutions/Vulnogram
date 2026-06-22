// Copyright (c) 2017 Chandan B N. All rights reserved.

const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/user');
const config = require('./conf');
const pbkdf2 = require('../lib/pbkdf2.js');
const crypto = require('crypto');

const NAME_OK = /[a-zA-Z0-9]{3,64}/;

function hashPassword(pw) {
    return new Promise(function (resolve, reject) {
        pbkdf2.hash(pw, function (err, h) { if (err) { reject(err); } else { resolve(h); } });
    });
}

// Generate a username that satisfies /^[a-zA-Z0-9]{3,64}$/ and does not collide
// with an existing user. Usernames are stored lower-cased, so we build lower-case.
async function uniqueUsername(claims, email) {
    var raw = claims.preferred_username || (email ? email.split('@')[0] : '') || claims.name || 'user';
    var base = String(raw).toLowerCase().replace(/[^a-z0-9]/g, '');
    if (base.length < 3) { base = 'user' + base; }
    base = base.substring(0, 56);
    var candidate = base;
    for (var i = 0; i < 20; i++) {
        var existing = await User.findOne({ username: candidate });
        if (!existing) { return candidate; }
        candidate = (base + crypto.randomBytes(2).toString('hex')).substring(0, 64);
    }
    return (base + crypto.randomBytes(6).toString('hex')).substring(0, 64);
}

let oidcIssuer = null;

// Resolve an OIDC login to a Vulnogram user: match by stable (iss,sub), else link
// an existing local account by email, else just-in-time create a new user. Returns
// { user } on success or { message } to reject with a friendly reason.
async function handleOidcUser(tokenset, userinfo) {
    var o = config.oidc || {};
    var claims = userinfo || (tokenset && typeof tokenset.claims === 'function' ? tokenset.claims() : {}) || {};
    var iss = (oidcIssuer && oidcIssuer.metadata && oidcIssuer.metadata.issuer) || claims.iss;
    var sub = claims.sub;
    var email = (claims.email || '').toLowerCase();

    if (!sub) { return { message: 'SSO did not return a subject id.' }; }
    if (!email) { return { message: 'SSO did not return an email address.' }; }
    if (o.requireVerifiedEmail && claims.email_verified !== true) {
        return { message: 'Your SSO email address is not verified.' };
    }
    if (Array.isArray(o.allowedDomains) && o.allowedDomains.length) {
        var domain = (email.split('@')[1] || '');
        if (o.allowedDomains.indexOf(domain) < 0) {
            return { message: 'This email domain is not allowed to sign in.' };
        }
    }

    // 1. Existing OIDC identity (stable across email changes).
    var byOidc = await User.findOne({ 'oidc.iss': iss, 'oidc.sub': sub });
    if (byOidc) {
        if (byOidc.active === false) { return { message: 'Account disabled.' }; }
        return { user: byOidc };
    }

    // 2. Link by email onto an existing local account.
    var byEmail = await User.findOne({ email: email });
    if (byEmail) {
        if (byEmail.oidc && byEmail.oidc.sub && byEmail.oidc.sub !== sub) {
            return { message: 'An account with this email is already linked to a different SSO identity.' };
        }
        if (byEmail.active === false) { return { message: 'Account disabled.' }; }
        var linked = await User.findOneAndUpdate(
            { _id: byEmail._id },
            { $set: { oidc: { iss: iss, sub: sub } } },
            { new: true }
        );
        return { user: linked || Object.assign({}, byEmail, { oidc: { iss: iss, sub: sub } }) };
    }

    // 3. Just-in-time create. New SSO users get the model's default role/team.
    var displayName = claims.name
        || [claims.given_name, claims.family_name].filter(Boolean).join(' ')
        || claims.preferred_username
        || email.split('@')[0];
    var username = await uniqueUsername(claims, email);
    if (!displayName || !NAME_OK.test(displayName)) { displayName = username; }
    // No usable local password: store a proper hash of a random secret so a local
    // login attempt fails safely (a non-hash sentinel would make pbkdf2.compare
    // read a bogus iteration count and hang).
    var hashed = await hashPassword(crypto.randomBytes(32).toString('hex'));
    var newUser = {
        name: displayName,
        email: email,
        username: username,
        oidc: { iss: iss, sub: sub },
        emoji: '',
        password: hashed
    };
    var err = User.validateUserDocument(newUser);
    if (err) { return { message: 'Could not create SSO account: ' + err.message }; }
    var created = await User.findOneAndUpdate(
        { username: username },
        newUser,
        { upsert: true, setDefaultsOnInsert: true, new: true }
    );
    if (!created) { created = await User.findOne({ username: username }); }
    return { user: created };
}

// openid-client Strategy verify (arity 3 => userinfo is fetched and passed in).
function oidcVerify(tokenset, userinfo, done) {
    handleOidcUser(tokenset, userinfo).then(function (res) {
        if (res && res.user) { return done(null, res.user); }
        return done(null, false, { message: (res && res.message) || 'SSO sign-in failed.' });
    }).catch(function (e) {
        done(e);
    });
}

// Discover the IdP and register the 'oidc' passport strategy. Fire-and-forget at
// boot; on success sets config.oidc.ready so the login button appears and the
// routes accept SSO. Any failure leaves SSO disabled without crashing the app.
async function setupOidc(passport) {
    var o = config.oidc;
    if (!o || !o.enabled || !o.issuer || !o.clientID || !o.clientSecret || !o.callbackURL) {
        return false;
    }
    var oc;
    try {
        oc = require('openid-client');
    } catch (e) {
        console.warn('OIDC is enabled but the "openid-client" package is not installed; SSO disabled.');
        return false;
    }
    oidcIssuer = await oc.Issuer.discover(o.issuer);
    var client = new oidcIssuer.Client({
        client_id: o.clientID,
        client_secret: o.clientSecret,
        redirect_uris: [o.callbackURL],
        response_types: ['code']
    });
    passport.use('oidc', new oc.Strategy(
        { client: client, params: { scope: (o.scopes && o.scopes.join(' ')) || 'openid profile email' }, usePKCE: 'S256' },
        oidcVerify
    ));
    config.oidc.ready = true;
    console.log('OIDC SSO enabled (issuer ' + (oidcIssuer.metadata && oidcIssuer.metadata.issuer) + ')');
    return true;
}

module.exports = function (passport) {
    // Local username/password strategy (always available as a fallback).
    passport.use(new LocalStrategy(function (username, password, done) {
        User.findOne({ username: username }, function (err, user) {
            if (err) { return done(err); }
            if (!user) {
                return done(null, false, { message: 'No user found' });
            }
            if (user.active === false) {
                return done(null, false, { message: 'Account disabled' });
            }
            try {
                pbkdf2.compare(password, user.password, function (cmpErr, same) {
                    if (cmpErr) { return done(null, false, { message: 'Wrong password' }); }
                    if (same) { return done(null, user); }
                    return done(null, false, { message: 'Wrong password' });
                });
            } catch (e) {
                // Malformed/sentinel hash (e.g. an SSO-only account): treat as no match.
                return done(null, false, { message: 'Wrong password' });
            }
        });
    }));

    passport.serializeUser(function (user, done) {
        done(null, String(user._id || user.id));
    });

    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            if (err) { return done(err); }
            // A user deactivated mid-session is treated as logged out on the next request.
            if (user && user.active === false) { return done(null, false); }
            done(null, user);
        });
    });

    // Register OIDC in the background (network discovery). Never blocks boot.
    setupOidc(passport).catch(function (e) {
        console.error('OIDC setup failed:', e && e.message ? e.message : e);
    });
};

module.exports.setupOidc = setupOidc;
