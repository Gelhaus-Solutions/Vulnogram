// Best-effort workflow notifications. When a CVE's internal-workflow stage
// changes, notify the document's watchers (and the people named in CNA_private:
// owner/assignees/reviewers/approvers) via email and/or an outbound webhook.
//
// Entirely OPT-IN via conf.notifications and a no-op when disabled/unconfigured.
// Every path is wrapped so this NEVER throws — a notification failure must not be
// able to break a save. Triggered once, from the REST save chokepoint in
// routes/onedoc.js (not the realtime patch path), so a stage change fires exactly
// one notification.

const conf = require('../config/conf');
const mongo = require('./mongo');
const crypto = require('crypto');

function notifyConf() {
    return (conf && conf.notifications) || {};
}

function isEnabled() {
    return !!notifyConf().enabled;
}

// Recipient usernames = watchers + CNA_private.people roles, minus the actor.
function collectRecipientUsernames(doc, actor) {
    var set = {};
    function add(u) {
        if (u && typeof u === 'string') { set[u] = true; }
    }
    if (doc && Array.isArray(doc.watchers)) {
        doc.watchers.forEach(add);
    }
    var people = doc && doc.body && doc.body.CNA_private && doc.body.CNA_private.people;
    if (people && typeof people === 'object') {
        add(people.owner);
        ['assignees', 'reviewers', 'approvers'].forEach(function (k) {
            if (Array.isArray(people[k])) { people[k].forEach(add); }
        });
    }
    if (actor && actor.username) {
        delete set[actor.username]; // don't notify whoever made the change
    }
    return Object.keys(set);
}

async function resolveEmails(usernames) {
    if (!usernames.length || !mongo.isConnected()) {
        return [];
    }
    try {
        var users = await mongo.getCollection('users')
            .find(
                { username: { $in: usernames }, active: { $ne: false } },
                { projection: { username: 1, email: 1 } }
            )
            .toArray();
        return users
            .map(function (u) { return u && u.email; })
            .filter(function (e) { return typeof e === 'string' && e.indexOf('@') > 0; });
    } catch (e) {
        return [];
    }
}

function buildPayload(doc, fromState, toState, actor) {
    var base = (notifyConf().baseURL || '').replace(/\/+$/, '');
    return {
        event: 'cve.stage_change',
        id: doc ? doc.id : undefined,
        from: (fromState === undefined ? null : fromState),
        to: (toState === undefined ? null : toState),
        actor: actor ? actor.username : undefined,
        team: doc ? doc.team : undefined,
        url: (base && doc && doc.id) ? (base + '/cve/' + encodeURIComponent(doc.id)) : undefined,
        at: new Date().toISOString()
    };
}

// Lazy, memoized mail transport so a missing/unconfigured nodemailer install can
// never break startup or a save — it's only require()d when email is enabled.
let _transport = null;
let _transportTried = false;
function getTransport() {
    if (_transportTried) { return _transport; }
    _transportTried = true;
    var n = notifyConf();
    if (!n.email || !n.email.enabled) { return (_transport = null); }
    try {
        var nodemailer = require('nodemailer');
        _transport = nodemailer.createTransport(n.email.transport || {});
    } catch (e) {
        console.log('notify: email transport unavailable (' + (e && e.message ? e.message : e) + ')');
        _transport = null;
    }
    return _transport;
}

async function sendEmail(emails, subject, text) {
    var n = notifyConf();
    if (!n.email || !n.email.enabled || !emails.length) { return; }
    var transport = getTransport();
    if (!transport) { return; }
    try {
        await transport.sendMail({
            from: n.email.from || undefined,
            to: emails.join(', '),
            subject: subject,
            text: text
        });
    } catch (e) {
        console.log('notify: email send failed: ' + (e && e.message ? e.message : e));
    }
}

async function postWebhook(url, secret, payload) {
    if (!url) { return; }
    var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var timer = controller ? setTimeout(function () { controller.abort(); }, 5000) : null;
    try {
        var body = JSON.stringify(payload);
        var headers = { 'Content-Type': 'application/json' };
        if (secret) {
            // HMAC-SHA256 over the exact request body, so receivers can verify
            // authenticity + integrity instead of trusting a shared secret echoed
            // in the header. Receivers verify with a timing-safe compare.
            headers['X-Vulnogram-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
        }
        await fetch(url, {
            method: 'POST',
            headers: headers,
            body: body,
            signal: controller ? controller.signal : undefined
        });
    } catch (e) {
        console.log('notify: webhook POST failed: ' + (e && e.message ? e.message : e));
    } finally {
        if (timer) { clearTimeout(timer); }
    }
}

async function sendWebhooks(payload, team) {
    var n = notifyConf();
    var hooks = [];
    if (n.webhook && n.webhook.enabled && n.webhook.url) {
        hooks.push({ url: n.webhook.url, secret: n.webhook.secret });
    }
    // Optional per-team endpoint (team.settings.webhook).
    if (team && team.settings && team.settings.webhook) {
        hooks.push({ url: team.settings.webhook, secret: (n.webhook && n.webhook.secret) });
    }
    for (var i = 0; i < hooks.length; i++) {
        await postWebhook(hooks[i].url, hooks[i].secret, payload);
    }
}

// doc: { id, team, watchers, body }  (body carries CNA_private.people)
async function sendStageChange(doc, fromState, toState, actor, team) {
    if (!isEnabled()) { return; }
    var n = notifyConf();
    if (n.events && n.events.stageChange === false) { return; }
    try {
        var payload = buildPayload(doc, fromState, toState, actor);
        await sendWebhooks(payload, team);
        if (n.email && n.email.enabled) {
            var emails = await resolveEmails(collectRecipientUsernames(doc, actor));
            if (emails.length) {
                var label = (doc && doc.id) ? doc.id : 'A CVE';
                var subject = '[Vulnogram] ' + label + ' → ' + (toState || '');
                var lines = [
                    label + ' workflow stage changed.',
                    '',
                    'From: ' + (fromState || '(none)'),
                    'To:   ' + (toState || '(none)'),
                    'By:   ' + (actor ? actor.username : 'unknown')
                ];
                if (payload.url) { lines.push('', payload.url); }
                await sendEmail(emails, subject, lines.join('\n'));
            }
        }
    } catch (e) {
        console.log('notify: sendStageChange error: ' + (e && e.message ? e.message : e));
    }
}

module.exports = {
    sendStageChange: sendStageChange,
    collectRecipientUsernames: collectRecipientUsernames
};
