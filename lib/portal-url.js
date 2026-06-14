// Normalize a CVE Services endpoint URL to a canonical form for byte-equal
// comparison/storage. MUST match the client-side normalizePortalUrl() in
// default/cve5/portal.js so a doc's stored `source` equals req.session.activeSource.
function normalizePortalUrl(url) {
    return String(url || '').trim().replace(/\/+$/, '');
}

module.exports = { normalizePortalUrl: normalizePortalUrl };
