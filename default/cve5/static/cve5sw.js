//
// CveServices - Service Worker Middleware
// Filename: sw.js
//
// Author: Ben N
//
// Description: Handles exchange of API requests with credentials.
//
// Copyright 2022, Ben Nott <pajexali@gmail.com>.
// See LICENSE for a full copy of the license.
//

const storage = {};
const keyname = "cve-services.vulnogramkeyStore";
/* Encryption API using JavaScript native crypto.js and indexeDB for storing private keys */
const encrypt_storage_version = "1.1.14";
const cacheName = 'private';
const cacheURL = '/creds';
// Opt-in "remember API key" store. Unlike the session cache (cacheURL) this is
// NOT cleared on session timeout, only on explicit logout / forget, so the key
// can auto-restore a session across timeouts and page reloads. The key stays
// encrypted at rest with the per-user RSA key and never leaves the worker.
const rememberCacheURL = (org, user) => '/creds-remember/' + encodeURIComponent(org) + '/' + encodeURIComponent(user);
// Remembered keys expire after this long; an expired entry is treated as absent
// (and deleted) on the next read so a stale key can't silently auto-login forever.
// Entries written before this version have no rememberedAt and never expire.
const REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
function isRememberExpired(result) {
    return !!(result && result.rememberedAt && (Date.now() - result.rememberedAt > REMEMBER_TTL_MS));
}

destroySession = () => {
    if ('creds' in storage) {
        delete storage['creds'];
        let bc = new BroadcastChannel('logout');
        bc.postMessage({ 'error': 'LOGOUT', message: 'The user has logged out' });
    }
    caches.open(cacheName).then(cache => {
        cache.delete(cacheURL);
    });
};

setSessionTimer = () => {
    let defaultTimeout = 1000 * 60 * 60; //1 hour timeout

    setTimeout(
        destroySession,
        defaultTimeout
    );
};

setCredentials = (e) => {
    let remember = !!e.data.creds.remember;
    storage.creds = { user: e.data.creds.user, org: e.data.creds.org, key: e.data.creds.key };
    check_create_key(e.data.creds.user).then(function (newkey) {
        encryptMessage(e.data.creds.key, newkey.publicKey)
            .then(function (encBuffer) {
                arrayBuffertoURI(encBuffer)
                    .then(function (encURL) {
                        let f = { user: e.data.creds.user, org: e.data.creds.org, keyURL: encURL };
                        clientReply(e, { data: "ok" });
                        caches.open(cacheName).then(function (cache) {
                            cache.put(cacheURL, new Response(JSON.stringify(f)));
                            if (remember) {
                                let rf = { user: f.user, org: f.org, keyURL: f.keyURL, rememberedAt: Date.now() };
                                cache.put(rememberCacheURL(f.org, f.user), new Response(JSON.stringify(rf)));
                            }
                        });
                        setSessionTimer();
                    });
            });
    });
};

// Restore a session from the persistent "remember" store (no key exposed to page).
loginRemembered = async (e) => {
    try {
        let { org, user } = e.data;
        let cache = await caches.open(cacheName);
        let resp = await cache.match(rememberCacheURL(org, user));
        if (!resp) { return clientReply(e, { error: "NO_REMEMBER" }); }
        let result = await resp.json();
        if (isRememberExpired(result)) {
            await cache.delete(rememberCacheURL(org, user));
            return clientReply(e, { error: "NO_REMEMBER" });
        }
        let ekey = await check_create_key(result.user);
        let encBuffer = URItoarrayBuffer(result.keyURL);
        let rawKey = await decryptMessage(encBuffer, ekey.privateKey);
        storage.creds = { user: result.user, org: result.org, key: rawKey };
        await cache.put(cacheURL, new Response(JSON.stringify({ user: result.user, org: result.org, keyURL: result.keyURL })));
        setSessionTimer();
        clientReply(e, { data: "ok" });
        let bc = new BroadcastChannel('login');
        bc.postMessage({ message: 'The user has logged in' });
    } catch (err) {
        clientReply(e, { error: "NO_REMEMBER" });
    }
};

hasRemembered = async (e) => {
    try {
        let cache = await caches.open(cacheName);
        let resp = await cache.match(rememberCacheURL(e.data.org, e.data.user));
        if (resp) {
            let result = await resp.json();
            if (isRememberExpired(result)) {
                await cache.delete(rememberCacheURL(e.data.org, e.data.user));
                return clientReply(e, { remembered: false });
            }
        }
        clientReply(e, { remembered: !!resp });
    } catch (err) {
        clientReply(e, { remembered: false });
    }
};

// List saved logins that have a (non-expired) remembered key on THIS device.
// Returns only {org, user, rememberedAt} — never any key material.
listRemembered = async (e) => {
    let out = [];
    try {
        let cache = await caches.open(cacheName);
        let keys = await cache.keys();
        for (let req of keys) {
            let path;
            try { path = new URL(req.url).pathname; } catch (err) { continue; }
            if (path.indexOf('/creds-remember/') !== 0) { continue; }
            let parts = path.substring('/creds-remember/'.length).split('/');
            if (parts.length < 2) { continue; }
            let entry = { org: decodeURIComponent(parts[0]), user: decodeURIComponent(parts[1]), rememberedAt: null };
            try {
                let resp = await cache.match(req);
                if (resp) {
                    let result = await resp.json();
                    if (isRememberExpired(result)) { await cache.delete(req); continue; }
                    entry.rememberedAt = result.rememberedAt || null;
                }
            } catch (err) { /* skip a single unreadable entry */ }
            out.push(entry);
        }
    } catch (err) { /* ignore */ }
    clientReply(e, { entries: out });
};

forgetRemembered = async (e) => {
    try {
        let cache = await caches.open(cacheName);
        await cache.delete(rememberCacheURL(e.data.org, e.data.user));
    } catch (err) { /* ignore */ }
    clientReply(e, "ok");
};

clientReply = (e, msg) => {
    e.ports[0].postMessage(msg);
};

deadSession = (e, debugString) => {
    clientReply(e, {
        error: "NO_SESSION",
        message: "Please login."
        //debug: debugString
    });
    return false;
}

checkSession = async (e) => {
    if (!('creds' in storage)) {
        try {
            let cache = await caches.open(cacheName);
            let cachecreds = await cache.match(cacheURL);
            if (cachecreds) {
                let result = await cachecreds.json();
                let ekey = await check_create_key(result.user);
                let encBuffer = URItoarrayBuffer(result.keyURL);
                let rawKey = await decryptMessage(encBuffer, ekey.privateKey);
                result.key = rawKey;
                delete result.keyURL;
                storage.creds = JSON.parse(JSON.stringify(result));
                return true;
            } else {
                return deadSession(e);
            }
        } catch (err) {
            return deadSession(e, String(err));
        }
    };
    return true;
};

defaultOpts = () => {
    return {
        headers: {
            'content-type': 'application/json',
            'CVE-API-KEY': storage.creds.key,
            'CVE-API-ORG': storage.creds.org,
            'CVE-API-USER': storage.creds.user,
        },
    };
};

getURL = (path, query) => {
    let url = new URL(`/api/${path}`, storage.serviceUri);

    if (query) {
        for (const [k, v] of Object.entries(query)) {
            // Append array values as repeated keys so the API receives a real
            // array (e.g. active_roles.add=CNA&active_roles.add=ADP).
            if (Array.isArray(v)) {
                v.forEach(function (item) { url.searchParams.append(k, item); });
            } else {
                url.searchParams.append(k, v);
            }
        }
    }

    return url.toString();
};

doFetch = (event, url, opts) => {
    return fetch(url, opts)
        .then(res => {
            if (res.ok) {
                res.json().then(data => clientReply(event, data));
            } else {
                res.json().then(msg => {
                    clientReply(event, msg);
                });
            }
        })
        .catch(err => {
            clientReply(event, { error: err });
        });
};

requestService = (event) => {
    let { query, path, method } = event.data;

    let opts = defaultOpts();
    let url = getURL(path, query);

    if (['PUT', 'POST'].includes(method)) {
        opts.method = method;

        if ('body' in event.data) {
            opts.body = JSON.stringify(event.data.body);
        }
    }

    return doFetch(event, url, opts);
};

self.onmessage = e => {
    switch (e.data.type) {
        case 'init':
            if ('serviceUri' in e.data) {
                storage.serviceUri = e.data.serviceUri;
                clientReply(e, 'ok');
            }
            break;
        case 'echo':
            clientReply(e, 'echo');
            break;
        case 'login':
            setCredentials(e);
            break;
        case 'loginRemembered':
            loginRemembered(e);
            break;
        case 'hasRemembered':
            hasRemembered(e);
            break;
        case 'listRemembered':
            listRemembered(e);
            break;
        case 'forget':
            forgetRemembered(e);
            break;
        case 'request':
            checkSession(e).then(function (success) {
                if (success)
                    requestService(e);
                else
                    clientReply(e, { error: "NO_SESSION" });
            });
            break;
        case 'getOrg':
            checkSession(e).then(function (success) {
                if (success)
                    clientReply(e, storage.creds.org);
                else
                    clientReply(e, { error: "NO_SESSION" })
            });
            break;
        case 'getSession':
            checkSession(e).then(function (success) {
                if (success) {
                    clientReply(e, {
                        user: storage.creds.user,
                        org: storage.creds.org
                    });
                } else {
                    clientReply(e, { error: "NO_SESSION" });
                }
            });
            break;
        case 'destroy':
            destroySession();
            clientReply(e, "Cleaning up session");
            break;
        default:
            clientReply(e, { error: 'Not supported' });
            break;
    }
};

async function encryptMessage(message, publicKey) {
    let encoded = new TextEncoder().encode(message);
    let ciphertext = await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP"
        },
        publicKey,
        encoded
    );
    return ciphertext;
}
async function decryptMessage(ciphertext, privateKey) {
    let decrypted = await crypto.subtle.decrypt(
        {
            name: "RSA-OAEP"
        },
        privateKey,
        ciphertext
    );

    let dec = new TextDecoder();
    return dec.decode(decrypted);
}
async function arrayBuffertoURI(arrayBuffer) {
    let blob = new Blob([arrayBuffer]);
    return new Promise((resolve) => {
        let reader = new FileReader()
        reader.onloadend = function () {
            resolve(reader.result);
        };
        reader.readAsDataURL(blob);
    });
}
function URItoarrayBuffer(URI) {
    var byteString = atob(URI.split(',')[1]);
    var arrayBuffer = new ArrayBuffer(byteString.length);
    var _ia = new Uint8Array(arrayBuffer);
    for (var i = 0; i < byteString.length; i++) {
        _ia[i] = byteString.charCodeAt(i);
    }
    return arrayBuffer;
}


async function sha256sum(msg) {
    let enc = new TextEncoder().encode(msg);
    const buff = await crypto.subtle.digest('SHA-256', enc);
    const barray = Array.from(new Uint8Array(buff));
    let hex = barray.map(function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
    return hex;
};
function dbManager(user, key, sum) {
    return new Promise(function (resolve, reject) {
        var open = indexedDB.open(keyname, 1);
        open.onupgradeneeded = function () {
            var db = open.result;
            if (!db.objectStoreNames.contains("keyStore")) {
                var store = db.createObjectStore("keyStore",
                    { keyPath: "user" });
                var index = store.createIndex("sigIndex", ["sum.sha256"]);
            }
        };
        open.onsuccess = function () {
            var db = open.result;
            var tx = db.transaction("keyStore", "readwrite");
            var store = tx.objectStore("keyStore");
            if (key) {
                store.put({ user: user, key: key, sum: sum });
            } else {
                if (user) {
                    var getUser = store.get(user);
                    getUser.onsuccess = function (q) {
                        resolve(q);
                    };
                } else if (sum.sha256) {
                    var index = store.index("sigIndex");
                    var getSum = index.get([sum.sha256]);
                    getSum.onsuccess = function (q) {
                        resolve(q);
                    };
                } else {
                    reject("A user or a checksum is required");
                }
            };
            tx.oncomplete = function () {
                db.close();
            };
        }
    });
}

async function save_key(user, key) {
    let fpb = await crypto.subtle.exportKey("jwk", key.publicKey);
    let sum = { sha256: await sha256sum(fpb.n) };
    dbManager(user, key, sum);
    return key;
}

async function check_create_key(user) {
    let dbKey = await dbManager(user);
    if (('target' in dbKey) && (dbKey.target.result) &&
        (dbKey.target.result.user == user)) {
        return dbKey.target.result.key;
    }
    return crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        false,
        ["encrypt", "decrypt"]
    ).then(function (key) {
        save_key(user, key);
        return key;
    });
}
