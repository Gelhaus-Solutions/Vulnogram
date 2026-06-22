// Copyright (c) 2017 Chandan B N. All rights reserved.

const crypto = require('crypto');

const saltBytes = 16;
const hashBytes = 32;
const iterations = 100599;
const digest = 'sha512';
const version = 1;
const encoding = 'base64';
module.exports = {
    hash: function (password, callback) {
        crypto.randomBytes(saltBytes, function (err, salt) {
            if (err) {
                return callback(err);
            }
            crypto.pbkdf2(password, salt, iterations, hashBytes, digest,
                function (err, hash) {
                    if (err) {
                        return callback(err);
                    }
                    var result = Buffer.alloc(12 + hash.length + salt.length);
                    // save version (4bytes) + salt length (4bytes) + iteration count (4bytes) + salt + hash.
                    result.writeUInt32BE(version, 0);
                    result.writeUInt32BE(salt.length, 4);
                    result.writeUInt32BE(iterations, 8);
                    salt.copy(result, 12);
                    hash.copy(result, salt.length + 12);
                    callback(null, result.toString(encoding));
                });
        });
    },
    compare: function (password, shadow, callback) {
        if (!password || !shadow) {
            // empty passwords or empty shadow == no login!
            return callback(null, false);
        }
        var stored = Buffer.from(shadow, encoding);
        var saltLen = stored.length >= 12 ? stored.readUInt32BE(4) : 0;
        var iters = stored.length >= 12 ? stored.readUInt32BE(8) : 0;
        var keyLen = stored.length - saltLen - 12;
        // Reject a malformed/sentinel shadow (e.g. an SSO-only account) WITHOUT
        // running pbkdf2: a bogus saltLen/keyLen would otherwise throw, and a bogus
        // (huge) iteration count would hang the process. Real hashes use ~100k iters.
        if (saltLen <= 0 || keyLen <= 0 || saltLen + 12 > stored.length || iters <= 0 || iters > 5000000) {
            return callback(null, false);
        }
        var salt = stored.slice(12, saltLen + 12);
        var expected = stored.slice(saltLen + 12);
        crypto.pbkdf2(password, salt, iters, keyLen, digest, function (err, verify) {
            if (err) {
                return callback(null, false);
            }
            // constant-time comparison (equal length guaranteed by keyLen === expected.length)
            var ok = verify.length === expected.length && crypto.timingSafeEqual(verify, expected);
            callback(null, ok);
        });
    }
}