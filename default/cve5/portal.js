//CVE Services Client and Portal GUI 

var csClient = undefined;
var defaultPortalUrl = 'https://cveawg.mitre.org/api';

var csCache = {
    portalType: 'production',
    url: defaultPortalUrl,
    org: null,
    user: null,
    orgInfo: null
}
var portalBootstrapPromise = null;
var portalNavStatePromise = null;
var cvePortalFilterChoice = {
    fstate: 'RESERVED',
    y: null
};

function setPortalNavConnectionState(connected) {
    var nav = document.getElementById('cvePortalNav');
    if (!nav) {
        return;
    }
    var status = connected ? 'connected' : 'disconnected';
    nav.setAttribute('data-portal-status', status);
    nav.setAttribute('title', connected ? 'CVE Services connected' : 'CVE Services disconnected (login required)');
}

async function refreshPortalNavConnectionState() {
    if (!('serviceWorker' in navigator)) {
        setPortalNavConnectionState(false);
        return false;
    }
    if (portalNavStatePromise) {
        return portalNavStatePromise;
    }
    portalNavStatePromise = (async function () {
        try {
            await ensurePortalBootstrap();
        } catch (e) {
            setPortalNavConnectionState(false);
            return false;
        }
        try {
            var hasSession = await hasActivePortalSession(csCache.url);
            setPortalNavConnectionState(hasSession);
            return hasSession;
        } catch (e) {
            setPortalNavConnectionState(false);
            return false;
        }
    })();
    try {
        return await portalNavStatePromise;
    } finally {
        portalNavStatePromise = null;
    }
}

function initPortalNavConnectionState() {
    setPortalNavConnectionState(false);
    refreshPortalNavConnectionState();
    window.addEventListener('focus', refreshPortalNavConnectionState);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPortalNavConnectionState);
} else {
    initPortalNavConnectionState();
}

// ---- Root / Secretariat role detection -----------------------------------
// CVE Services org roles: 'CNA', 'ADP', 'ROOT_CNA', 'SECRETARIAT'. A Secretariat
// org is also a Root, so it sees both portals.
function getOrgActiveRoles(orgInfo) {
    if (orgInfo && orgInfo.authority && Array.isArray(orgInfo.authority.active_roles)) {
        return orgInfo.authority.active_roles.map(function (r) { return String(r).toUpperCase(); });
    }
    return [];
}

function orgIsSecretariat(orgInfo) {
    return getOrgActiveRoles(orgInfo).indexOf('SECRETARIAT') >= 0;
}

function orgIsRoot(orgInfo) {
    var roles = getOrgActiveRoles(orgInfo);
    return roles.indexOf('SECRETARIAT') >= 0 || roles.indexOf('ROOT_CNA') >= 0 || roles.indexOf('ROOT') >= 0;
}

function applyPortalRoleVisibility(orgInfo) {
    // The Root portal stays hidden for now: CVE Services has not implemented Root
    // organizations yet (all cross-org management is Secretariat-only), so a pure
    // ROOT_CNA has no root-specific actions available. The scaffolding is kept so
    // it can be enabled once CVE Services grants roots those powers.
    var rootNav = document.getElementById('cveRootPortalNav');
    var secNav = document.getElementById('cveSecretariatPortalNav');
    if (rootNav) { rootNav.classList.add('hid'); }
    if (secNav) { secNav.classList.toggle('hid', !orgIsSecretariat(orgInfo)); }
}

function hidePortalRoleButtons() {
    var rootNav = document.getElementById('cveRootPortalNav');
    var secNav = document.getElementById('cveSecretariatPortalNav');
    if (rootNav) { rootNav.classList.add('hid'); }
    if (secNav) { secNav.classList.add('hid'); }
}

function isPortalAuthError(e) {
    const err = e && e.error ? e.error : null;
    return err == 'NO_SESSION' || err == 'UNAUTHORIZED';
}

function normalizePortalUrl(url) {
    if (!url) {
        return defaultPortalUrl;
    }
    return String(url).trim().replace(/\/+$/, '');
}

function getClientPortalUrl() {
    if (!csClient || !csClient._middleware) {
        return null;
    }
    return normalizePortalUrl(csClient._middleware.serviceUri);
}

function ensureCsClient(url) {
    const targetUrl = normalizePortalUrl(url);
    const currentUrl = getClientPortalUrl();
    if (!csClient || currentUrl !== targetUrl) {
        csClient = new CveServices(targetUrl, "./static/cve5sw.js");
    }
    return csClient;
}

function clearPortalSessionCache() {
    const settings = getStoredPortalSettings();
    csCache = {
        portalType: settings.portalType,
        url: settings.portalUrl,
        org: null,
        user: null,
        orgInfo: null
    };
    window.localStorage.removeItem('cveApi');
    setPortalNavConnectionState(false);
    hidePortalRoleButtons();
}

async function hasActivePortalSession(url) {
    if (!('serviceWorker' in navigator)) {
        setPortalNavConnectionState(false);
        return false;
    }
    const targetUrl = normalizePortalUrl(url || csCache.url || getStoredPortalSettings().portalUrl);
    csCache.url = targetUrl;
    csClient = ensureCsClient(targetUrl);
    const restored = await restorePortalCacheFromSession();
    if (!(restored && csCache.user && csCache.org)) {
        setPortalNavConnectionState(false);
        return false;
    }
    // Verify session against CVE Services, not just cached SW credentials.
    try {
        var orgInfo = await csClient.getOrgInfo();
        csCache.orgInfo = orgInfo;
        applyPortalRoleVisibility(orgInfo);
        setPortalNavConnectionState(true);
        return true;
    } catch (e) {
        if (isPortalAuthError(e)) {
            if (csClient && typeof csClient.logout === 'function') {
                try {
                    await csClient.logout();
                } catch (e2) {
                    // ignore cleanup errors
                }
            }
            clearPortalSessionCache();
            return false;
        }
        throw e;
    }
}

function setPortalSidebarState(show) {
    var portalDialog = document.getElementById('cvePortalDialog');
    var portalNav = document.getElementById('cvePortalNav');
    if (!portalDialog) {
        return false;
    }
    if (!portalDialog._portalEventsBound) {
        portalDialog.addEventListener('close', function () {
            var nav = document.getElementById('cvePortalNav');
            if (nav) {
                nav.classList.remove('active');
            }
        });
        portalDialog._portalEventsBound = true;
    }
    if (show) {
        if (!portalDialog.open) {
            portalDialog.showModal();
        }
        if (portalNav) {
            portalNav.classList.add('active');
        }
    } else {
        if (portalDialog.open) {
            portalDialog.close();
        }
        if (portalNav) {
            portalNav.classList.remove('active');
        }
    }
    return show;
}

function closeCvePortal(event) {
    if (event && event.preventDefault) {
        event.preventDefault();
    }
    setPortalSidebarState(false);
    return false;
}

function showCvePortal(event, forceShow) {
    if (event && event.preventDefault) {
        event.preventDefault();
    }
    var portalDialog = document.getElementById('cvePortalDialog');
    if (!portalDialog) {
        return false;
    }
    var show = forceShow === true ? true : !portalDialog.open;
    if (!show) {
        setPortalSidebarState(false);
        return false;
    }
    setPortalSidebarState(true);
    var portalFeedback = new feedback(document.getElementById('port'), 'spinner');
    showPortalViewOrLogin()
        .finally(function () {
            portalFeedback.cancel();
        });
    return false;
}

async function showPortalViewOrLogin() {
    if (!('serviceWorker' in navigator)) {
        document.getElementById('port').innerHTML = '<h2 class="pad2 tred">Browser does not support Service Workers feature required for this tab.</h2><i class="indent pad2">Are you using Firefox in Private mode? Try normal mode.</i>';
        setPortalSidebarState(true);
        return false;
    }
    try {
        await ensurePortalBootstrap();
    } catch (e) {
        portalErrorHandler(e);
        return false;
    }
    loadPortalCache();
    if (!csCache.url) {
        csCache.url = getStoredPortalSettings().portalUrl;
    }
    let hasSession = false;
    try {
        hasSession = await hasActivePortalSession(csCache.url);
    } catch (e) {
        portalErrorHandler(e);
        return false;
    }
    if (!hasSession) {
        var autoOk = false;
        try { autoOk = await tryRememberedAutoLogin(); } catch (e) { autoOk = false; }
        if (autoOk) {
            await showPortalView();
            setPortalSidebarState(true);
            return true;
        }
        showPortalLogin();
        setPortalSidebarState(true);
        return false;
    }
    await showPortalView();
    setPortalSidebarState(true);
    return true;
}

// Auto-login from a remembered (encrypted, on-device) key for the last org/user.
async function tryRememberedAutoLogin() {
    var org = (csCache && csCache.org) || window.localStorage.getItem('shortName');
    var user = csCache && csCache.user;
    if (!user) {
        try { user = (JSON.parse(window.localStorage.getItem('cveApi') || '{}')).user; } catch (e) { user = null; }
    }
    if (!org || !user || !csClient) { return false; }
    var has = await csClient.hasRemembered(org, user);
    if (!has || !has.remembered) { return false; }
    try {
        var r = await csClient.loginRemembered(org, user);
        if (r === 'ok' || (r && r.data === 'ok')) {
            csCache.org = org;
            csCache.user = user;
            window.localStorage.setItem('shortName', org);
            window.localStorage.setItem('cveApi', JSON.stringify(csCache));
            return true;
        }
    } catch (e) { /* NO_REMEMBER */ }
    return false;
}

function portalFocusEditor() {
    setPortalSidebarState(false);
    if (typeof (mainTabGroup) !== 'undefined') {
        mainTabGroup.change(0);
    }
}

// ---- Root / Secretariat management portals --------------------------------
var ROOT_PORTAL_SCOPE = {
    key: 'root', dialogId: 'cveRootPortalDialog', containerId: 'rootPort',
    pfx: 'root', title: 'CVE Root Portal', icon: 'vgi-king', roleLabel: 'Root'
};
var SEC_PORTAL_SCOPE = {
    key: 'secretariat', dialogId: 'cveSecretariatPortalDialog', containerId: 'secPort',
    pfx: 'sec', title: 'CVE Secretariat Portal', icon: 'vgi-cog', roleLabel: 'Secretariat'
};

function closeManagementPortal(dialogId, event) {
    if (event && event.preventDefault) { event.preventDefault(); }
    var dlg = document.getElementById(dialogId);
    if (dlg && dlg.open) { dlg.close(); }
    return false;
}
function closeCveRootPortal(event) { return closeManagementPortal('cveRootPortalDialog', event); }
function closeCveSecretariatPortal(event) { return closeManagementPortal('cveSecretariatPortalDialog', event); }

async function showCveManagementPortal(scope) {
    var dlg = document.getElementById(scope.dialogId);
    var container = document.getElementById(scope.containerId);
    if (!dlg || !container) { return false; }
    if (!dlg.open) { dlg.showModal(); }
    var fb = new feedback(container, 'spinner');
    try {
        await ensurePortalBootstrap();
        var hasSession = await hasActivePortalSession(csCache.url);
        if (!hasSession) {
            container.innerHTML = '<div class="pad2"><b class="tred">Please log in to the CVE CNA Portal first,</b> then reopen this portal.</div>';
            return false;
        }
        var orgInfo = csCache.orgInfo || await csClient.getOrgInfo();
        var allowed = scope.key === 'secretariat' ? orgIsSecretariat(orgInfo) : orgIsRoot(orgInfo);
        if (!allowed) {
            container.innerHTML = '<div class="pad2"><b class="tred">Your CVE Services org does not have the ' + scope.roleLabel + ' role.</b></div>';
            return false;
        }
        container.innerHTML = cveRender({
            ctemplate: 'mgmtPortalShell',
            pfx: scope.pfx,
            scopeTitle: scope.title,
            scopeIcon: scope.icon,
            orgInfo: orgInfo
        });
        await renderManagementPortal(scope, orgInfo);
        return true;
    } catch (e) {
        portalErrorHandler(e);
        return false;
    } finally {
        fb.cancel();
    }
}

function showCveRootPortal(event) {
    if (event && event.preventDefault) { event.preventDefault(); }
    showCveManagementPortal(ROOT_PORTAL_SCOPE);
    return false;
}
function showCveSecretariatPortal(event) {
    if (event && event.preventDefault) { event.preventDefault(); }
    showCveManagementPortal(SEC_PORTAL_SCOPE);
    return false;
}

async function renderManagementPortal(scope, orgInfo) {
    var body = document.getElementById(scope.pfx + 'MgmtBody');
    if (!body) { return; }
    if (scope.key === 'secretariat') {
        body.innerHTML = cveRender({ ctemplate: 'secPortalBody', orgInfo: orgInfo });
        await secLoadOrgs(1);
    } else {
        // Root orgs are not implemented in CVE Services yet (button is hidden).
        body.innerHTML = cveRender({ ctemplate: 'rootPortalBody', orgInfo: orgInfo });
    }
}

// ---- Secretariat management portal ---------------------------------------
var secMgmt = { orgPage: 1 };

function secMgmtSetStatus(msg, isError) {
    var el = document.getElementById('secMgmtStatus');
    if (el) {
        el.innerText = msg || '';
        el.className = 'pad' + (isError ? ' tred' : '');
    }
}

// Surface CVE Services errors (rejected objects carry .error / .message / .details).
function secErr(e) {
    if (!e) { return 'Unknown error'; }
    if (typeof e === 'string') { return e; }
    if (e.message) { return e.message; }
    if (e.error && typeof e.error === 'string') { return e.error; }
    return 'Request failed';
}

function secActiveRoles(org) {
    return (org && org.authority && Array.isArray(org.authority.active_roles)) ? org.authority.active_roles.slice() : [];
}

function secCheckedRoles(form) {
    var roles = [];
    var boxes = form.querySelectorAll('input[name="role"]:checked');
    for (var i = 0; i < boxes.length; i++) { roles.push(boxes[i].value); }
    return roles;
}

async function secLoadOrgs(page) {
    secMgmt.orgPage = page || 1;
    var tbody = document.getElementById('secOrgRows');
    if (!tbody) { return; }
    var fb = new feedback(tbody, 'spinner');
    try {
        secMgmtSetStatus('');
        var data = await csClient.listOrgs({ page: secMgmt.orgPage });
        if (data && data.error) { secMgmtSetStatus(secErr(data), true); return; }
        var orgs = (data && data.organizations) ? data.organizations : [];
        tbody.innerHTML = cveRender({ ctemplate: 'secOrgRows', orgs: orgs });
        secRenderOrgPagination(data);
    } catch (e) {
        secMgmtSetStatus(secErr(e), true);
    } finally {
        fb.cancel();
    }
}

function secRenderOrgPagination(data) {
    var el = document.getElementById('secOrgPage');
    if (!el) { return; }
    if (data && (data.nextPage || data.prevPage)) {
        el.classList.remove('hid');
        var per = data.itemsPerPage || (data.organizations ? data.organizations.length : 0);
        var start = ((data.currentPage || 1) - 1) * per + 1;
        var end = start + (data.organizations ? data.organizations.length : 0) - 1;
        var info = document.getElementById('secOrgPageInfo');
        if (info) { info.innerText = 'Showing ' + start + '–' + end + (data.totalCount ? (' of ' + data.totalCount) : ''); }
        var cur = document.getElementById('secCurrentPage');
        if (cur) { cur.innerText = data.currentPage || 1; }
        var prev = document.getElementById('secPrevPage');
        if (prev) { prev.style.display = data.prevPage ? 'block' : 'none'; }
        var next = document.getElementById('secNextPage');
        if (next) { next.style.display = data.nextPage ? 'block' : 'none'; }
    } else {
        el.classList.add('hid');
    }
}

function secPaginate(delta) {
    secLoadOrgs(Math.max(1, secMgmt.orgPage + delta));
    return false;
}

async function secOrgLookup() {
    var input = document.getElementById('secOrgFilter');
    var name = input ? (input.value || '').trim() : '';
    if (!name) { secLoadOrgs(1); return; }
    await secOpenOrg(name);
}

async function secOpenOrg(shortName) {
    var detail = document.getElementById('secOrgDetail');
    if (!detail) { return; }
    var fb = new feedback(detail, 'spinner');
    try {
        secMgmtSetStatus('');
        var org = await csClient.getOrgByName(shortName);
        if (!org || org.error || !org.short_name) {
            secMgmtSetStatus(secErr(org || ('Org ' + shortName + ' not found')), true);
            detail.innerHTML = '';
            return;
        }
        var quota = null, users = [];
        try { quota = await csClient.getOrgIdQuotaFor(shortName); if (quota && quota.error) { quota = null; } } catch (e) { quota = null; }
        try { var ur = await csClient.getOrgUsersFor(shortName); users = (ur && ur.users) ? ur.users : []; } catch (e) { users = []; }
        detail.innerHTML = cveRender({ ctemplate: 'secOrgDetailView', org: org, quota: quota, users: users });
        if (detail.scrollIntoView) { detail.scrollIntoView({ block: 'nearest' }); }
    } catch (e) {
        secMgmtSetStatus(secErr(e), true);
    } finally {
        fb.cancel();
    }
}

function secShowCreateOrg() {
    var slot = document.getElementById('secOrgCreate');
    if (!slot) { return; }
    slot.classList.remove('hid');
    slot.innerHTML = cveRender({ ctemplate: 'secCreateOrgForm' });
}

async function secCreateOrg(event, form) {
    if (event && event.preventDefault) { event.preventDefault(); }
    var roles = secCheckedRoles(form);
    if (!roles.length) { cveShowError('Select at least one role.'); return false; }
    var body = {
        short_name: form.short_name.value.trim(),
        name: form.name.value.trim(),
        authority: { active_roles: roles },
        policies: { id_quota: parseInt(form.id_quota.value, 10) || 0 }
    };
    try {
        var r = await csClient.createOrg(body);
        if (r && r.error) { cveShowError(r); return false; }
        var slot = document.getElementById('secOrgCreate');
        if (slot) { slot.classList.add('hid'); slot.innerHTML = ''; }
        secMgmtSetStatus(body.short_name + ' created.');
        await secLoadOrgs(1);
        await secOpenOrg(body.short_name);
    } catch (e) {
        cveShowError(e);
    }
    return false;
}

async function secEditOrg(shortName) {
    var detail = document.getElementById('secOrgDetail');
    if (!detail) { return; }
    var slot = detail.querySelector('#secEditSlot');
    if (!slot) {
        slot = document.createElement('div');
        slot.id = 'secEditSlot';
        slot.className = 'gap';
        detail.appendChild(slot);
    }
    try {
        var org = await csClient.getOrgByName(shortName);
        if (!org || org.error) { cveShowError(org || 'Org not found'); return; }
        var quota = null;
        try { quota = await csClient.getOrgIdQuotaFor(shortName); if (quota && quota.error) { quota = null; } } catch (e) { quota = null; }
        slot.innerHTML = cveRender({ ctemplate: 'secEditOrgForm', org: org, roles: secActiveRoles(org), quota: quota });
    } catch (e) {
        cveShowError(e);
    }
}

async function secSubmitEditOrg(event, form, shortName) {
    if (event && event.preventDefault) { event.preventDefault(); }
    try {
        var org = await csClient.getOrgByName(shortName);
        var current = secActiveRoles(org).map(function (r) { return String(r).toUpperCase(); });
        var wanted = secCheckedRoles(form).map(function (r) { return String(r).toUpperCase(); });
        var addRoles = wanted.filter(function (r) { return current.indexOf(r) < 0; });
        var removeRoles = current.filter(function (r) { return wanted.indexOf(r) < 0; });
        var params = {};
        if (form.name.value.trim() && form.name.value.trim() !== org.name) { params.name = form.name.value.trim(); }
        if (form.new_short_name.value.trim()) { params.new_short_name = form.new_short_name.value.trim(); }
        var q = parseInt(form.id_quota.value, 10);
        if (!isNaN(q)) { params.id_quota = q; }
        if (addRoles.length) { params['active_roles.add'] = addRoles; }
        if (removeRoles.length) { params['active_roles.remove'] = removeRoles; }
        if (Object.keys(params).length === 0) { secMgmtSetStatus('No changes.'); return false; }
        var r = await csClient.updateOrg(shortName, params);
        if (r && r.error) { cveShowError(r); return false; }
        secMgmtSetStatus(shortName + ' updated.');
        var newName = params.new_short_name || shortName;
        await secLoadOrgs(secMgmt.orgPage);
        await secOpenOrg(newName);
    } catch (e) {
        cveShowError(e);
    }
    return false;
}

async function secSetQuota(shortName, current) {
    var v = window.prompt('New ID quota for ' + shortName + ':', current);
    if (v === null) { return; }
    var n = parseInt(v, 10);
    if (isNaN(n) || n < 0) { cveShowError('Quota must be a non-negative number.'); return; }
    try {
        var r = await csClient.setOrgIdQuota(shortName, n);
        if (r && r.error) { cveShowError(r); return; }
        secMgmtSetStatus('Quota for ' + shortName + ' set to ' + n + '.');
        await secOpenOrg(shortName);
        secLoadOrgs(secMgmt.orgPage);
    } catch (e) {
        cveShowError(e);
    }
}

function secShowAddUser(shortName) {
    var slot = document.getElementById('secAddUserSlot');
    if (!slot) { return; }
    slot.innerHTML = cveRender({ ctemplate: 'secAddUserForm', shortName: shortName });
}

function secShowSecret(message, secret) {
    var sd = document.getElementById('secretDialog');
    var sf = document.getElementById('secretDialogForm');
    var um = document.getElementById('userMessage');
    if (sd && sf) {
        sf.pass.value = secret;
        sf.pass.type = 'password';
        if (um) { um.innerText = message || ''; }
        sd.showModal();
    } else {
        cveShowError({ error: 'API secret', message: (message || '') + ' Secret: ' + secret });
    }
}

async function secSubmitAddUser(event, form, shortName) {
    if (event && event.preventDefault) { event.preventDefault(); }
    var roles = [];
    if (form.admin && form.admin.checked) { roles.push('ADMIN'); }
    var userInfo = {
        username: form.username.value.trim(),
        name: { first: form.first.value.trim(), last: form.last.value.trim() },
        authority: { active_roles: roles }
    };
    try {
        var r = await csClient.createOrgUserFor(shortName, userInfo);
        if (r && r.error) { cveShowError(r); return false; }
        var slot = document.getElementById('secAddUserSlot');
        if (slot) { slot.innerHTML = ''; }
        if (r && r.created && r.created.secret) {
            secShowSecret(r.message || (userInfo.username + ' created.'), r.created.secret);
        }
        await secOpenOrg(shortName);
    } catch (e) {
        cveShowError(e);
    }
    return false;
}

async function secResetUser(shortName, username) {
    if (!window.confirm('Reset API key for ' + username + ' in ' + shortName + '? The old key stops working.')) { return; }
    try {
        var r = await csClient.resetOrgUserApiKeyFor(shortName, username);
        if (r && r.error) { cveShowError(r); return; }
        if (r && r['API-secret']) {
            secShowSecret('API key reset for ' + username + '.', r['API-secret']);
        }
    } catch (e) {
        cveShowError(e);
    }
}

async function secToggleAdmin(shortName, username, isAdmin) {
    var params = {};
    if (isAdmin) { params['active_roles.remove'] = 'ADMIN'; } else { params['active_roles.add'] = 'ADMIN'; }
    try {
        var r = await csClient.updateOrgUserFor(shortName, username, params);
        if (r && r.error) { cveShowError(r); return; }
        await secOpenOrg(shortName);
    } catch (e) {
        cveShowError(e);
    }
}

async function secToggleActive(shortName, username, isActive) {
    try {
        var r = await csClient.updateOrgUserFor(shortName, username, { active: isActive ? 'false' : 'true' });
        if (r && r.error) { cveShowError(r); return; }
        await secOpenOrg(shortName);
    } catch (e) {
        cveShowError(e);
    }
}

// Program-wide CVE ID lookup (Secretariat). GET /cve-id/{id} resolves any org's
// ID for a secretariat, returning its state and owning CNA.
async function secCveLookup() {
    var input = document.getElementById('secCveSearch');
    var out = document.getElementById('secCveResult');
    if (!input || !out) { return; }
    var id = normalizeCveIdQuery(input.value);
    if (!id) { out.innerHTML = '<i class="tgrey">Enter a CVE ID such as CVE-' + currentYear + '-1234.</i>'; return; }
    var fb = new feedback(out, 'spinner');
    try {
        var rec = await csClient.getCveId(id);
        if (!rec || rec.error || !rec.cve_id) {
            out.innerHTML = '<i class="tred">' + id + ' not found.</i>';
            return;
        }
        out.innerHTML = cveRender({ ctemplate: 'secCveResult', rec: rec });
    } catch (e) {
        out.innerHTML = '<i class="tred">' + (secErr ? secErr(e) : (id + ' not found.')) + '</i>';
    } finally {
        fb.cancel();
    }
}

function getStoredPortalSettings() {
    let portalType = window.localStorage.getItem('portalType');
    let portalUrl = window.localStorage.getItem('portalUrl');
    if (!portalType || !portalUrl) {
        portalType = 'production';
        portalUrl = defaultPortalUrl;
    }
    return {
        portalType: portalType,
        portalUrl: portalUrl
    };
}

function loadPortalCache() {
    if (!window.localStorage.getItem('cveApi')) {
        return;
    }
    try {
        const cache = JSON.parse(window.localStorage.getItem('cveApi'));
        if (cache && typeof cache === 'object') {
            csCache = cache;
        } else {
            window.localStorage.removeItem('cveApi');
        }
    } catch (e) {
        window.localStorage.removeItem('cveApi');
    }
}

async function restorePortalCacheFromSession() {
    if (!csClient || typeof csClient.getSession !== 'function') {
        return false;
    }
    try {
        const session = await csClient.getSession();
        if (!session || !session.user || !session.org) {
            return false;
        }
        const settings = getStoredPortalSettings();
        csCache.user = session.user;
        csCache.org = session.org;
        csCache.url = csCache.url ? csCache.url : settings.portalUrl;
        csCache.portalType = csCache.portalType ? csCache.portalType : settings.portalType;
        csCache.orgInfo = csCache.orgInfo ? csCache.orgInfo : null;
        window.localStorage.setItem('cveApi', JSON.stringify(csCache));
        window.localStorage.setItem('shortName', session.org);
        return true;
    } catch (e) {
        return false;
    }
}

async function bootstrapCsClient() {
    if (!('serviceWorker' in navigator)) {
        return false;
    }
    loadPortalCache();
    if (!csCache.url) {
        csCache.url = getStoredPortalSettings().portalUrl;
    }
    csClient = ensureCsClient(csCache.url);
    listenforLogins();
    listenforLogouts();
    return true;
}

function ensurePortalBootstrap() {
    if (!portalBootstrapPromise) {
        portalBootstrapPromise = bootstrapCsClient().catch(function (e) {
            portalBootstrapPromise = null;
            throw e;
        });
    }
    return portalBootstrapPromise;
}

async function initCsClient() {
    if ('serviceWorker' in navigator) {
        try {
            await ensurePortalBootstrap();
            const hasSession = await hasActivePortalSession(csCache.url);
            if (hasSession) {
                await showPortalView();
            } else {
                clearPortalSessionCache();
            }
        } catch (e) {
            portalErrorHandler(e);
        }
    }
}

// Saved CNA login profiles (item 6). Metadata only — the API key is never stored
// server-side; the user still types it into the login box each session.
var cnaProfilesCache = [];
async function cnaLoadProfiles() {
    var sel = document.getElementById('cpProfile');
    if (!sel) { return; }
    try {
        var res = await fetch('/users/cna/json', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } });
        if (!res.ok) { return; }
        var data = await res.json();
        cnaProfilesCache = data.profiles || [];
        sel.innerHTML = '<option value="">— manual entry —</option>' + cnaProfilesCache.map(function (p) {
            return '<option value="' + p.id + '">' + String(p.label || (p.org + '/' + p.user)).replace(/</g, '&lt;') + '</option>';
        }).join('');
        // Repopulate the portal endpoint dropdown from instance-configured services.
        var portalEl = document.getElementById('cpPortal');
        if (portalEl && Array.isArray(data.services) && data.services.length) {
            var current = portalEl.value;
            portalEl.innerHTML = data.services.map(function (s) {
                return '<option value="' + s.url + '">' + String(s.label || s.url).replace(/</g, '&lt;') + '</option>';
            }).join('');
            for (var i = 0; i < portalEl.options.length; i++) {
                if (portalEl.options[i].value === current) { portalEl.selectedIndex = i; break; }
            }
        }
    } catch (e) { /* ignore */ }
}
function cnaProfileSelect(sel) {
    var p = cnaProfilesCache.find(function (x) { return x.id === sel.value; });
    if (!p) { return; }
    var portalEl = document.getElementById('cpPortal');
    var orgEl = document.getElementById('cpOrg');
    var userEl = document.getElementById('cpUser');
    var keyEl = document.getElementById('cpKey');
    if (orgEl) { orgEl.value = p.org || ''; }
    if (userEl) { userEl.value = p.user || ''; }
    if (portalEl && p.serviceUrl) {
        for (var i = 0; i < portalEl.options.length; i++) {
            if (portalEl.options[i].value === p.serviceUrl) { portalEl.selectedIndex = i; break; }
        }
    }
    // If this saved login has a remembered API key on this device, auto-login
    // instead of asking the user to re-enter it.
    (async function () {
        try {
            var url = normalizePortalUrl(p.serviceUrl || (portalEl ? portalEl.value : csCache.url));
            csClient = ensureCsClient(url);
            var has = await csClient.hasRemembered(p.org, p.user);
            if (has && has.remembered) {
                var r = await csClient.loginRemembered(p.org, p.user);
                if (r === 'ok' || (r && r.data === 'ok')) {
                    csCache.org = p.org;
                    csCache.user = p.user;
                    csCache.url = url;
                    csCache.portalType = portalEl ? portalEl.options[portalEl.selectedIndex].text : csCache.portalType;
                    window.localStorage.setItem('shortName', p.org);
                    window.localStorage.setItem('portalType', csCache.portalType);
                    window.localStorage.setItem('portalUrl', url);
                    window.localStorage.setItem('cveApi', JSON.stringify(csCache));
                    await refreshRecentCveEntries(p.org);
                    await showPortalView();
                    setPortalSidebarState(true);
                    setTimeout(portalLogout, defaultTimeout);
                    return;
                }
            }
        } catch (e) { /* fall through to manual entry */ }
        if (keyEl) { keyEl.focus(); }
    })();
}

function showPortalLogin(message) {
    clearPortalSessionCache();

    document.getElementById('port').innerHTML = cveRender({
        ctemplate: 'cveLoginBox',
        message: message,
        prevPortal: csCache.portalType,
        prevOrg: window.localStorage.getItem('shortName')
    })
    cnaLoadProfiles();
}

async function portalLogout(message, forget) {
    // Explicit logout (forget=true) also clears the remembered key so the user
    // stays logged out; the auto session timeout keeps it (forget falsy).
    if (forget && csClient && csCache.org && csCache.user) {
        try { await csClient.forgetKey(csCache.org, csCache.user); } catch (e) { /* ignore */ }
    }
    if (csClient != null) {
        await csClient.logout();
    }
    clearPortalSessionCache();
    setPortalSidebarState(false);
    if (document.getElementById('loginErr')) {
        document.getElementById("loginErr").innerText = message ? message : '';
    } else if (document.getElementById('port')) {
        document.getElementById('port').innerHTML = '';
    }
}

// Log out of the current CVE Services session and reopen the login box (which
// shows the saved-login picker), so a user can switch between saved CNA profiles.
async function cveSwitchLogin() {
    // Keep remembered keys so the user can pick another saved login that
    // auto-logs in; only explicit Logout forgets the key.
    await portalLogout();
    if (typeof showPortalLogin === 'function') {
        showPortalLogin();
    }
    if (typeof setPortalSidebarState === 'function') {
        setPortalSidebarState(true);
    }
}

async function showPortalView(orgInfo, userInfo) {
    try {
        var filterForm = document.getElementById("cvePortalFilter");
        if (filterForm) {
            if (filterForm.fstate) {
                cvePortalFilterChoice.fstate = filterForm.fstate.value + '';
            }
            if (filterForm.y && filterForm.y.value) {
                cvePortalFilterChoice.y = filterForm.y.value + '';
            }
        }
        if (!orgInfo) {
            orgInfo = await csClient.getOrgInfo();
        }
        csCache.orgInfo = orgInfo;
        applyPortalRoleVisibility(orgInfo);
        if (!userInfo) {
            userInfo = await csClient.getOrgUser(csCache.user);
        }
        // ID quota is informational — never block the portal if it fails.
        var idQuota = null;
        try {
            idQuota = await csClient.getOrgIdQuota();
        } catch (e) {
            idQuota = null;
        }
        document.getElementById('port').innerHTML = cveRender({
            portalType: csCache.portalType,
            portalURL: csCache.url,
            ctemplate: 'portal',
            filterState: cvePortalFilterChoice.fstate,
            filterYear: cvePortalFilterChoice.y ? cvePortalFilterChoice.y : (
                typeof currentYear !== 'undefined' ? (currentYear + '') : ((new Date()).getFullYear() + '')
            ),
            userInfo: userInfo,
            org: orgInfo,
            idQuota: idQuota
        });
        setPortalNavConnectionState(true);
        var button1 = document.getElementById('post1');
        if(button1) {
            if(csCache.portalType == 'test') {
                button1.innerText = 'Post to Test Portal'
            } else {
                button1.innerText = 'Publish CVE'
            }
        }
        var button2 = document.getElementById("post2")
        if(button2) {
            if(csCache.portalType == 'test') {
                button2.innerText = 'Post to Test Portal'
            } else {
                button2.innerText = 'Publish CVE';
            }
        }
        return await cveGetList();
    } catch (e) {
        portalErrorHandler(e);
    }
}

var loginChannel = new BroadcastChannel("login");
var logoutChannel = new BroadcastChannel("logout");

function listenforLogins() {
    loginChannel.onmessage = function (a) {
        initCsClient();
        refreshPortalNavConnectionState();
    }
}
function listenforLogouts() {
    logoutChannel.onmessage = function (a) {
        clearPortalSessionCache();
        setPortalSidebarState(false);
        if (document.getElementById('loginErr')) {
            document.getElementById("loginErr").innerText = a.message ? a.message : '';
        } else if (document.getElementById('port')) {
            document.getElementById('port').innerHTML = '';
        }
    }
}
function normalizeShortName(shortName) {
    if (!shortName) return null;
    return String(shortName).trim().toLowerCase().replace(/\s+/g, '_');
}

async function refreshRecentCveEntries(shortName) {
    if (typeof loadRecentAbbreviatedIds !== 'function') {
        return;
    }
    var orgName = normalizeShortName(shortName);
    if (!orgName) {
        return;
    }
    try {
        var recent = await loadRecentAbbreviatedIds(orgName);
        if (typeof window !== 'undefined' && typeof window.setRecentCveEntries === 'function') {
            window.setRecentCveEntries(recent, orgName);
        }
    } catch (e) {
        console.error('Failed to refresh recent CVE entries for ' + orgName, e);
    }
}

async function portalLogin(elem, credForm) {
    try {
        if (!('serviceWorker' in navigator)) {
            cveShowError('Browser is missing required features. Try a different browser that supports Service Workers.')
            return (false);
        }
        if (!credForm.checkValidity()) {
            return (false);
        }
        elem.preventDefault();
        var url = normalizePortalUrl(credForm.portal.value);
        var portalType = credForm.portal.options[credForm.portal.selectedIndex].text;
        var remember = !!(credForm.remember && credForm.remember.checked);
        csClient = ensureCsClient(url);
        var ret = await csClient.login(
            credForm.user.value,
            credForm.org.value,
            credForm.key.value,
            remember);
        if (!remember) {
            // Clear any previously remembered key for this login.
            try { await csClient.forgetKey(credForm.org.value, credForm.user.value); } catch (e) { /* ignore */ }
        }


        var orgInfo = await csClient.getOrgInfo();
        var userInfo = await csClient.getOrgUser(credForm.user.value);

        csCache.user = credForm.user.value;
        csCache.org = credForm.org.value;
        csCache.url = url;
        csCache.portalType = portalType;
        csCache.orgInfo = orgInfo;

        window.localStorage.setItem('cveApi', JSON.stringify(csCache));
        window.localStorage.setItem('portalType', portalType);
        window.localStorage.setItem('portalUrl', url);
        window.localStorage.setItem('shortName', credForm.org.value);

        if (ret == 'ok' || ret.data == "ok") {
            csCache.keyUrl = ret.keyUrl;
            await refreshRecentCveEntries(credForm.org.value);
            await showPortalView(orgInfo, userInfo);
            /* Add one hour session timeout in addition to timeout in serviceWorker */
            setTimeout(portalLogout, defaultTimeout);
            //announce to others that a login happened.
            loginChannel.postMessage({ message: 'The user has logged in' });

        } else {
            document.getElementById("loginErr").innerText = 'Failed to login: Possibly invalid credentials!';
        }
    } catch (e) {
        portalErrorHandler(e);
    }
}

function resetPortalLoginErr() {
    //console.log('changed form');
    document.getElementById("loginErr").innerText = '';
}


function portalErrorHandler(e) {
    const err = e && e.error ? e.error : null;
    const isNoSession = err == 'NO_SESSION';
    const isUnauthorized = err == 'UNAUTHORIZED';
    const isFetchError = !!(err && typeof err === 'object' && err.message == 'Failed to fetch');

    if (isFetchError) {
        const message = 'Error connecting to service';
        if (document.getElementById("loginErr")) {
            document.getElementById("loginErr").innerText = message;
        } else {
            cveShowError({ error: 'NETWORK_ERROR', message: message });
        }
        return;
    }

    if (isNoSession || isUnauthorized) {
        var loginErrNode = document.getElementById("loginErr");
        if (!loginErrNode && csClient && typeof csClient.logout === 'function') {
            csClient.logout().catch(function () { });
        }
        clearPortalSessionCache();
        const message = isUnauthorized ? 'Valid credentials required' : ((e && e.message) ? e.message : 'Please login.');
        if (document.getElementById("loginErr")) {
            // Login screen exists
            document.getElementById("loginErr").innerText = message;
        } else if (document.getElementById('port')) {
            showPortalLogin(message);
        } else {
            cveShowError({ error: err, message: message });
        }
    } else {
        cveShowError(e);
    }
}

async function userlistUpdate(elem, event) {
    if (elem.open) {
        document.getElementById("userStatsPopup").open = false;
        try {
            var ret = await csClient.getOrgUsers();
            var userlist = document.getElementById('userlist');
            if (userlist) {
                userlist.innerHTML = cveRender({
                    ctemplate: 'listUsers',
                    users: ret.users
                })
            }
        } catch (e) {
            portalErrorHandler(e);
        }
    }
}

async function cveUserKeyReset(elem, confirm) {
    var u = elem.form.u.value;
    var temp1 = document.getElementById("alertOk");
    if (confirm) {
        temp1.setAttribute("onclick", "document.getElementById('alertDialog').close();");
        elem.removeAttribute('id');
        document.getElementById('alertDialog').close();
    } else {
        showAlert("Are you sure?", "A new API key will be generated for user " + u + "! The old API key will no longer work!", undefined, true);
        let randid = Math.random().toString(32).substring(2);
        elem.setAttribute('id', randid);
        temp1.setAttribute('u', u);
        temp1.setAttribute('onclick', 'cveUserKeyReset(document.getElementById("' + randid + '"),true)');
        return;
    }
    try {
        var ret = await csClient.resetOrgUserApiKey(u);
        if (ret["API-secret"]) {
            var msg = "API Key was reset for " + u + "!";
            if (csCache.user == u) {
                msg += " You will need to login again with the new key!";
                portalLogout();
            }
            document.getElementById("userMessage").innerText = msg;
            document.getElementById("secretDialogForm").pass.value = ret["API-secret"];
            document.getElementById("secretDialogForm").pass.type = "password";
            document.getElementById("secretDialog").showModal();
        }
    } catch (e) {
        portalErrorHandler(e);
    }
}

async function cveUpdateUser(f) {
    try {
        params = {
            "name.first": f.first.value,
            "name.last": f.last.value
        };
        if (f.u.value != f.new_username.value) {
            params.new_username = f.new_username.value
        }
        if (csCache.user != f.u.value) {
            params.active = f.active.checked;
            // #187: prevent removing/deactivating the org's last active administrator.
            var willBeActiveAdmin = f.active.checked && f.admin.checked;
            if (!willBeActiveAdmin) {
                try {
                    var orgUsers = await csClient.getOrgUsers();
                    var admins = (orgUsers && orgUsers.users ? orgUsers.users : []).filter(function (u) {
                        return u && u.active && u.authority && Array.isArray(u.authority.active_roles) && u.authority.active_roles.indexOf('ADMIN') >= 0;
                    });
                    var targetIsLastAdmin = admins.length <= 1 && admins.some(function (u) { return u.username === f.u.value; });
                    if (targetIsLastAdmin) {
                        cveShowError({ error: 'Last administrator', message: 'Cannot remove or deactivate the last active administrator of this organization. Promote another user to admin first.' });
                        return;
                    }
                } catch (e) {
                    // If the admin count cannot be verified, fall through; CVE Services may still reject.
                }
            }
            if (f.admin.checked) {
                params["active_roles.add"] = 'ADMIN'
            } else {
                params["active_roles.remove"] = 'ADMIN'
            }
        }

        var ret = await csClient.updateOrgUser(f.u.value, params);
        if (ret.updated) {
            document.getElementById("userEditDialog").close();
            if (document.getElementById("userListPopup")) {
                userlistUpdate(document.getElementById("userListPopup"));
            }
            //the current user is updating self
            if ((csCache.user == f.u.value) && document.getElementById("cveUser")) {
                if (csCache.user != ret.updated.username) {
                    cveShowError({ error: 'Username changed!', message: 'Username successfully changed to ' + ret.updated.username + '! You will need to login again!' });
                    portalLogout();
                    return;
                }
                document.getElementById("cveUser").innerHTML =
                    cveRender({
                        ctemplate: 'userstats',
                        userInfo: ret.updated,
                        org: await csClient.getOrgInfo()
                    })
            }
        }
    } catch (e) {
        cveShowError(e);
    }
}

function removeErrors() {
    Array.from(document.getElementsByClassName('formError')).forEach(x => x.remove());
}

function addError(el) {
    var div = document.createElement('div');
    div.classList.add('formError');
    div.innerHTML = "Please provide a valid data";
    div.setAttribute('onclick', 'this.remove(); return false;');
    el.setAttribute('onfocus', 'removeErrors()');
    el.after(div);
}

function validateForm(f) {
    let isvalid = true;
    const controls = f.elements;
    for (let i = 0; i < controls.length; i++) {
        const x = controls[i];
        if (!isvalid)
            return;
        /* Needed is an alias for required to avoid showing
           red boxes unless a submit event is initiated. */
        if (x.getAttribute("needed"))
            x.setAttribute("required", "required");
        if ('validity' in x) {
            if ('valid' in x.validity) {
                isvalid = x.validity.valid;
                if (!isvalid)
                    addError(x);
            }
        }
    };
    return isvalid;
}

async function cveUserEdit(elem) {
    const f = document.getElementById('userEditForm');
    const userEditDialog = document.getElementById('userEditDialog');
    if (!elem || !f || !userEditDialog) {
        cveShowError({ error: 'UI_ERROR', message: 'User edit form is unavailable on this page.' });
        return;
    }
    f.u.value = elem.getAttribute('u');
    f.new_username.value = elem.getAttribute('u');
    f.first.value = elem.getAttribute('f');
    f.last.value = elem.getAttribute('l');
    f.admin.checked = elem.getAttribute('ad') ? true : false;
    f.active.checked = elem.getAttribute('ac') ? true : false;
    if (csCache.user == f.u.value) {
        if (!elem.getAttribute('ad')) {
            f.new_username.disabled = true;
        }
        f.admin.parentElement.setAttribute('class', 'hid');
        f.admin.setAttribute('disabled', true);
        f.active.setAttribute('disabled', true);
    } else {
        f.admin.parentElement.removeAttribute('class');
        f.admin.removeAttribute('disabled');
        f.active.removeAttribute('disabled');
    }
    userEditDialog.showModal();
}

async function cveAddUser(f) {
    if (validateForm(f)) {
        try {
            const userFields = {
                "username": f.new_username.value,
                "name": {
                    "first": f.first.value,
                    "last": f.last.value
                },
                "authority": {
                    "active_roles": []
                }
            }
            if (f.admin.checked) {
              userFields.authority.active_roles.push("ADMIN")
            }
            var ret = await csClient.createOrgUser(userFields);
            if (ret.created && ret.created.secret) {
                document.getElementById('userAddDialog').close();
                document.getElementById("secretDialogForm").pass.value = ret.created.secret;
                document.getElementById("secretDialogForm").pass.type = "password";
                document.getElementById("secretDialog").showModal();
                document.getElementById("userMessage").innerText = ret.message;
                f.reset()
                userlistUpdate({ open: true });
            }
        } catch (e) {
            portalErrorHandler(e);
        }

    } else {
        cveShowError('Please provide valid information!');
    }
}

// ---- Edit own org info (registry-only descriptive editor) -----------------
// Registry support is cached per session. CVE Services < 2.8 (e.g. production
// 2.6.4) has no registry routes, so this editor is unavailable there.
var cveRegistrySupported = null;

async function cveDetectRegistry() {
    if (cveRegistrySupported !== null) {
        return cveRegistrySupported;
    }
    try {
        var org = await csClient.getOrgRegistry(csCache.org);
        cveRegistrySupported = !!(org && !org.error && org.short_name);
    } catch (e) {
        cveRegistrySupported = false;
    }
    return cveRegistrySupported;
}

function splitLines(value) {
    if (!value) { return []; }
    return value.split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
}

async function cveEditOrgInfo() {
    var dlg = document.getElementById('cveOrgInfoDialog');
    var body = document.getElementById('cveOrgInfoBody');
    if (!dlg || !body) { return; }
    body.innerHTML = '<center class="pad2"><div class="spinner"></div></center>';
    if (!dlg.open) { dlg.showModal(); }
    try {
        var ok = await cveDetectRegistry();
        if (!ok) {
            body.innerHTML = '<div class="pad2 tgrey">Editing organization info requires a CVE Services instance that supports the registry API (2.8+). This instance does not, so org details are managed by the Secretariat.</div>';
            return;
        }
        var org = await csClient.getOrgRegistry(csCache.org);
        if (!org || org.error) { body.innerHTML = '<div class="pad2 tred">Could not load organization info.</div>'; return; }
        body.innerHTML = cveRender({ ctemplate: 'orgInfoEditForm', org: org });
    } catch (e) {
        body.innerHTML = '<div class="pad2 tred">' + (secErr ? secErr(e) : 'Error') + '</div>';
    }
}

async function cveSaveOrgInfo(event, form, shortName) {
    if (event && event.preventDefault) { event.preventDefault(); }
    var status = document.getElementById('cveOrgInfoStatus');
    try {
        // The registry update validates the whole org, so echo the required
        // identity/quota fields back unchanged alongside the edited fields.
        var current = await csClient.getOrgRegistry(shortName);
        var bodyOut = {
            short_name: shortName,
            authority: Array.isArray(current.authority) ? current.authority : [],
            id_quota: (typeof current.id_quota === 'number') ? current.id_quota : (current.policies ? current.policies.id_quota : undefined),
            contact_info: {
                emails: splitLines(form.emails.value),
                websites: splitLines(form.websites.value),
                phone: form.phone.value.trim()
            },
            industry: form.industry.value.trim(),
            disclosure_policy: form.disclosure_policy.value.trim(),
            product_list: form.product_list.value.trim(),
            charter_or_scope: form.charter_or_scope.value.trim(),
            advisory_locations: splitLines(form.advisory_locations.value)
        };
        if (status) { status.innerText = 'Saving…'; status.className = 'pad tgrey'; }
        var r = await csClient.updateOrgRegistry(shortName, bodyOut);
        if (r && r.error) { if (status) { status.innerText = secErr(r); status.className = 'pad tred'; } return false; }
        if (status) { status.innerText = (r && r.message) ? r.message : 'Saved.'; status.className = 'pad'; }
    } catch (e) {
        if (status) { status.innerText = secErr ? secErr(e) : 'Error'; status.className = 'pad tred'; }
    }
    return false;
}

async function cveRenderList(l, refreshEditor) {
    if (l && document.getElementById('cveList')) {
        var canInlineLoad = !!(document.getElementById('docEditor') && typeof loadJSON === 'function' && typeof mainTabGroup !== 'undefined');
        var docPathBase = '/' + ((typeof schemaName === 'string' && schemaName) ? schemaName : 'cve5') + '/';
        document.getElementById('cveList').innerHTML = cveRender({
            ctemplate: 'listIds',
            cveIds: l,
            editable: true,//(csCache.portalType == 'test')
            inlineLoad: canInlineLoad,
            docPathBase: docPathBase
        })
        if (l.length > 0) {
            new Tablesort(document.getElementById('cveListTable'));
        }
        if (refreshEditor && typeof docSchema !== 'undefined' && docSchema && typeof editorSetCveDatalist === 'function' && document.getElementById('root.cveMetadata.cveId-datalist')) {
            docSchema.definitions.cveId.examples = l.map(i => i.cve_id);
            editorSetCveDatalist(l);
        }
        var editableList = document.getElementById('editablelist');
        if (editableList) {
            editableList.innerHTML = cveRender({
                ctemplate: 'editables',
                cveIds: l
            })
        }
    }
}

async function editorSetCveDatalist(l) {
    document.getElementById('root.cveMetadata.cveId-datalist').innerHTML = cveRender({
        ctemplate: 'reserveds',
        cveIds: l
    })
}

function paginate(a) {
    let el = document.getElementById('cvePage');
    if (!el) {
        //console.log("Error cannot find template ");
        //console.log(a);
        return false;
    }
    let cp = parseInt(el.getAttribute('data-page'));
    if (isNaN(cp)) {
        //console.log("The data-page element is not pareable ");
        //console.log(cp);
        return false;
    }
    let np = cp + parseInt(a);
    var cveForm = document.getElementById("cvePortalFilter");
    cveForm.page = np;
    cveGetList();
    return false;
}

//var collator = new Intl.Collator(undefined, {numeric: true});
async function pageShow(ret) {
    let el = document.getElementById('cvePage');
    if (!el) {
        //console.log("Error cannot find template ");
        //console.log(ret);
        return;
    }
    el.style.display = 'block';
    el.setAttribute('data-page', ret.currentPage);
    let start = (ret.currentPage - 1) * ret.itemsPerPage + 1;
    let end = start + ret.itemsPerPage - 1;
    let total = ret.totalCount;
    if (end > total)
        end = total;
    document.getElementById('cvePageInfo').innerHTML = "Showing " +
        String(start) + " to " + String(end) + " of " +
        String(total) + " records "
    document.getElementById('currentPage').innerHTML = ret.currentPage
    if (ret.prevPage)
        document.getElementById('prevPage').style.display = 'block';
    else
        document.getElementById('prevPage').style.display = 'none';
    if (ret.nextPage)
        document.getElementById('nextPage').style.display = 'block';
    else
        document.getElementById('nextPage').style.display = 'none';
}

async function cveShowError(err) {
    if (!err) {
        err = { error: 'Error', message: 'Unknown error' };
    }
    var cveErrorContainer = document.getElementById('cveErrors');
    var cveErrorModal = document.getElementById('cveErrorsModal');
    if (cveErrorContainer && cveErrorModal && typeof cveRender === 'function') {
        cveErrorContainer.innerHTML = cveRender({
            ctemplate: 'cveErrors',
            err: err
        });
        cveErrorModal.showModal();
        return;
    }
    var fallbackMessage = (err && err.message) ? err.message : cvePublishErrorMessage(err);
    if (typeof showAlert === 'function') {
        showAlert('Error', fallbackMessage);
    } else if (typeof window !== 'undefined' && typeof window.alert === 'function') {
        window.alert('Error: ' + fallbackMessage);
    }
}

// Build a canonical CVE ID from a free-form search term (ID-only search).
// Accepts "CVE-2024-1234", "2024-1234", "2024 1234", etc.
function normalizeCveIdQuery(term) {
    if (!term) return null;
    var t = String(term).toUpperCase().trim();
    var full = t.match(/CVE[-\s]*(\d{4})[-\s]*(\d{3,})/);
    if (full) return 'CVE-' + full[1] + '-' + full[2];
    var pair = t.match(/(\d{4})[-\s]+(\d{3,})/);
    if (pair) return 'CVE-' + pair[1] + '-' + pair[2];
    return null;
}

function cvePortalSetStatus(msg) {
    var el = document.getElementById('cveStatusMessage');
    if (el) { el.innerText = msg || ''; }
}

function hideCvePagination() {
    var el = document.getElementById('cvePage');
    if (el) {
        el.removeAttribute('data-page');
        el.style.display = 'none';
    }
    var cveForm = document.getElementById('cvePortalFilter');
    if (cveForm) { cveForm.page = 0; }
}

// Exact CVE-ID lookup. CVE Services has no server-side free-text/title search,
// so search is ID-only via GET /cve-id/{id}, valid across every state.
async function cveSearchById(term) {
    var cveListFeedback = new feedback(document.getElementById('cveList'), 'spinner');
    try {
        var id = normalizeCveIdQuery(term);
        if (!id) {
            cveRenderList([]);
            hideCvePagination();
            cvePortalSetStatus('Enter a CVE ID such as CVE-' + currentYear + '-1234 to search.');
            return [];
        }
        cvePortalSetStatus('');
        var rec = await csClient.getCveId(id);
        if (!rec || rec.error || !rec.cve_id) {
            cveRenderList([]);
            hideCvePagination();
            cvePortalSetStatus(id + ' not found.');
            return [];
        }
        // Honour the state filter unless "All" is selected.
        var cveForm = document.getElementById('cvePortalFilter');
        var wantState = (cveForm && cveForm.fstate) ? (cveForm.fstate.value || '') : '';
        if (wantState && rec.state !== wantState) {
            cveRenderList([]);
            hideCvePagination();
            cvePortalSetStatus(id + ' is ' + rec.state + ', not ' + wantState + '. Choose "All" to view it.');
            return [];
        }
        cveRenderList([rec], false);
        hideCvePagination();
        return [rec];
    } catch (e) {
        cveRenderList([]);
        hideCvePagination();
        var idn = normalizeCveIdQuery(term);
        cvePortalSetStatus((idn || term) + ' not found.');
        return [];
    } finally {
        cveListFeedback.cancel();
    }
}

// Tracks the active (state|year) filter so paging persists but a filter change
// resets back to the first page.
var cvePortalFilterSig = null;

async function cveGetList() {
    var searchForm = document.getElementById('cvePortalFilter');
    var searchTerm = (searchForm && searchForm.q) ? (searchForm.q.value || '').trim() : '';
    if (searchTerm) {
        return await cveSearchById(searchTerm);
    }
    cvePortalSetStatus('');
    var currentReserved = true;
    var cveListFeedback = new feedback(document.getElementById('cveList'), 'spinner');
    var filter = {
        state: 'RESERVED',
        cve_id_year: currentYear
    }
    var cveForm = document.getElementById("cvePortalFilter");
    if (cveForm) {
        if (cveForm.fstate) {
            cvePortalFilterChoice.fstate = cveForm.fstate.value + '';
            if (cveForm.fstate.value) {
                filter.state = cveForm.fstate.value + '';
                if (filter.state != 'RESERVED') {
                    currentReserved = false;
                }
            } else {
                delete filter.state;
            }
        }
        if (cveForm.y) {
            filter.cve_id_year = cveForm.y.value + '';
            cvePortalFilterChoice.y = filter.cve_id_year;
            if (filter.cve_id_year != currentYear) {
                currentReserved = false;
            }
        }
        // Reset to page 1 when the filter changes; keep the page on pagination clicks.
        var sig = (filter.state || 'ALL') + '|' + (filter.cve_id_year || '');
        if (sig !== cvePortalFilterSig) {
            cvePortalFilterSig = sig;
            cveForm.page = 0;
        }
        if (cveForm.page) {
            filter.page = cveForm.page;
        }
    }
    try {
        var ret = await csClient.getCveIds(filter);
        if (ret.error) {
            cveShowError(ret);
        } else {
            var idList = [];
            var idState = {};
            if (ret && ret.cve_ids) {
                idList = ret.cve_ids;
                idList = idList.sort((b, a) => (a.reserved > b.reserved) ? 1 : ((b.reserved > a.reserved) ? -1 : 0));
                for (var i = 0; i < idList.length; i++) {
                    idState[idList[i].cve_id] = idList[i].state;
                }
            }
            cveRenderList(idList, currentReserved);
            if (ret && (ret.nextPage || ret.prevPage)) {
                pageShow(ret);
            } else {
                let el = document.getElementById('cvePage');
                if (el) {
                    el.removeAttribute('data-page');
                    el.style.display = 'none';
                }
                if (cveForm)
                    cveForm.page = 0;
            }
            return idList;
        }
    } catch (e) {
        cveShowError(e);
        cveRenderList([]);
        return ([]);
    } finally {
        cveListFeedback.cancel();
    }
}

async function cveReserve(yearOffset, number) {
    var year = currentYear + (yearOffset ? yearOffset : 0);
    try {
        var args = {
            amount: number > 0 && number <= 50 ? number : 1,
            // Request only one at this time to get four digits! Requesting more at time gives the 5 digit ids.
            // batch_type: 'nonsequential',
            cve_year: year,
            short_name: csCache.org
        };
        if (number > 1) {
            args.batch_type = 'sequential';
        }
        var json = await csClient.reserveCveIds(args);
        return json.cve_ids;
    } catch (e) {
        cveShowError(e.message);
    }
}

async function cveSelectLoad(event) {
    event.preventDefault();
    var loadFeedback = new feedback(document.getElementById('load1'), 'text', 'Loading...');
    try {
        await cveLoad(event.target.elements.id.value);
    } catch (e) {
        portalErrorHandler(e);
        cveShowError('Please login to CVE Portal. Your session may have expired!');
    } finally {
        loadFeedback.cancel();
    }
    return false;
}

function cveSyncLoadedUrl(cveId) {
    if (!cveId || typeof updateDraftHistory !== 'function') {
        return;
    }
    updateDraftHistory('./' + cveId, { id: cveId });
}

function cveLoadIntoEditor(res, cveId, message, edOpts) {
    loadJSON(res, cveId, message, edOpts);
    cveSyncLoadedUrl(cveId);
    portalFocusEditor();
}

async function cveLoadFromCveOrg(cveId, suppressErrors) {
    var loadFeedback = new feedback(document.getElementById('editorContent'), 'spinner');
    try {
        // Use the active CVE Services instance (test/prod/custom), not always production.
        var serviceUrl = normalizePortalUrl((csCache && csCache.url) ? csCache.url : getStoredPortalSettings().portalUrl);
        const response = await fetch(serviceUrl + '/cve/' + cveId, {
            method: 'GET',
            credentials: 'omit',
            headers: {
                'Accept': 'application/json, text/plain, */*'
            }
        });
        if (response.ok) {
            const data = await response.json();
            if (data && data.cveMetadata) {
                cveLoadIntoEditor(cveFixForVulnogram(data), cveId, "Loaded " + cveId + " from CVE Services");
                return data;
            }
        } else if (!suppressErrors) {
            errMsg.textContent = "CVE not found in CVE.org!";
            infoMsg.textContent = "";
            return null;
        }
    } catch (e) {
        if (!suppressErrors) {
            errMsg.textContent = "Failed to load valid CVE Record";
            infoMsg.textContent = "";
        }
        console.error('Failed to fetch from CVE.org:', e);
        return null;
    } finally {
        loadFeedback.cancel();
    }
    return null;
}


async function cveLoad(cveId) {
    var cveOrgRes = await cveLoadFromCveOrg(cveId, true);
    if (cveOrgRes) {
        return cveOrgRes;
    }

    if (!csClient || typeof csClient.getCve !== 'function') {
        errMsg.textContent = "CVE not found in CVE.org!";
        infoMsg.textContent = "";
        return null;
    }

    try {
        var res = await csClient.getCve(cveId);
        if (res.cveMetadata) {
            if (res.containers) {
                res = cveFixForVulnogram(res);
            } else {
                //console.log('no containers');
            }
            var edOpts = (res.cveMetadata.state == 'REJECTED') ? rejectEditorOption : publicEditorOption;
            var portalType = (csCache && csCache.portalType) ? csCache.portalType : 'production';
            cveLoadIntoEditor(res, cveId, "Loaded " + cveId + " from CVE Services (" + portalType + ")", edOpts);
            return res;
        }
    } catch (e) {
        if (e != '404' && e.error != 'CVE_RECORD_DNE') {
            errMsg.textContent = "Failed to load valid CVE Record";
            infoMsg.textContent = "";
            return null;
        }
    }

    var skeleton = {
        "cveMetadata": {
            "cveId": cveId,
            "assigner": csCache.orgInfo ? csCache.orgInfo.UUID : "",
        }
    };
    try {
        var res = await csClient.getCveId(cveId);
        var edOpts = publicEditorOption;
        if (res.state == 'RESERVED') {
            skeleton.cveMetadata.state = "PUBLISHED";
        } else if (res.state == 'REJECTED') {
            skeleton.cveMetadata.state = "REJECTED";
            edOpts = rejectEditorOption;
        } else {
            return {};
        }

        cveLoadIntoEditor(skeleton, cveId, "Loaded " + cveId, edOpts);
        return skeleton;
    } catch (e2) {
        if (e2 == '404') {
            showAlert('CVE Not found!');
        } else {
            errMsg.textContent = "Failed to load valid CVE Record";
            infoMsg.textContent = "";
        }
    }
    return null;
}

async function cveReject(elem, event) {
    var id = elem.getAttribute('data');
    if (window.confirm('Do you want to reject ' + id + '? It cannot be undone!')) {
        try {
            var ret = await csClient.updateCveId(id, 'REJECTED', csCache.org);
            if (ret.updated && ret.updated.state == 'REJECTED') {
                var m = document.getElementById("cveStatusMessage");
                m.innerText = "Rejected " + id;
                await cveGetList();
            }
        } catch (e) {
            portalErrorHandler(e);
        }
    }
}
function cveToggleSelectAll(el) {
    var boxes = document.querySelectorAll('#cveListTable .cveSelect');
    for (var i = 0; i < boxes.length; i++) { boxes[i].checked = el.checked; }
}

// Bulk-reject every selected RESERVED CVE ID (single confirmation).
async function cveRejectSelected() {
    var boxes = document.querySelectorAll('#cveListTable .cveSelect:checked');
    var ids = [];
    for (var i = 0; i < boxes.length; i++) {
        var id = boxes[i].getAttribute('data');
        if (id) { ids.push(id); }
    }
    if (!ids.length) { cveShowError('Select at least one reserved CVE ID to reject.'); return; }
    if (!window.confirm('Reject ' + ids.length + ' CVE ID(s)? This cannot be undone!\n\n' + ids.join(', '))) { return; }
    var m = document.getElementById('cveStatusMessage');
    var ok = 0, failed = [];
    for (var j = 0; j < ids.length; j++) {
        if (m) { m.innerText = 'Rejecting ' + (j + 1) + '/' + ids.length + ' (' + ids[j] + ')…'; }
        try {
            var ret = await csClient.updateCveId(ids[j], 'REJECTED', csCache.org);
            if (ret && ret.updated && ret.updated.state === 'REJECTED') { ok++; }
            else { failed.push(ids[j]); }
        } catch (e) {
            failed.push(ids[j]);
        }
    }
    if (m) {
        m.innerText = 'Rejected ' + ok + ' of ' + ids.length +
            (failed.length ? ('. Failed: ' + failed.join(', ')) : '.');
    }
    await cveGetList();
}

function transatePath(p) {
    if(p) {
        p = p.replace("/cnaContainer", "root.containers.cna");
        p = p.replaceAll('/', '.');
    }
    return p;
}

function filterADP(vr) {
    if (vr && vr.length > 0) {
        var filtered = vr.filter(a => a.path && a.path.startsWith('root.containers.adp') == 0);
        return filtered;
    }
    else { 
        return vr
    }
}

function cvePublishErrorMessage(e) {
    if (e == undefined || e == null) {
        return "Unknown error";
    }
    if (typeof e == 'string') {
        return e;
    }
    if (e.message) {
        return e.message;
    }
    if (e.error) {
        if (typeof e.error == 'string') {
            return e.error;
        }
        if (e.error.message) {
            return e.error.message;
        }
    }
    try {
        return JSON.stringify(e);
    } catch (e2) {
        return String(e);
    }
}

function cveAlert(title, message, timer) {
    if (typeof showAlert === 'function') {
        showAlert(title, message, timer);
        return;
    }
    var text = message ? (title + ': ' + message) : title;
    if (typeof window !== 'undefined' && typeof window.alert === 'function') {
        window.alert(text);
    } else {
        console.warn(text);
    }
}

function cveCloneDoc(doc) {
    if (!doc) {
        return doc;
    }
    if (typeof cloneJSON === 'function') {
        return cloneJSON(doc);
    }
    return JSON.parse(JSON.stringify(doc));
}

function cvePreparePublishDoc(doc) {
    var prepared = cveCloneDoc(doc);
    if (typeof textUtil !== 'undefined' && textUtil && typeof textUtil.reduceJSON === 'function') {
        prepared = textUtil.reduceJSON(prepared);
    }
    return prepared;
}

async function cveEnsurePublishSession() {
    try {
        await ensurePortalBootstrap();
    } catch (e) {
        portalErrorHandler(e);
        return false;
    }
    var hasSession = false;
    try {
        hasSession = await hasActivePortalSession(csCache.url);
    } catch (e) {
        portalErrorHandler(e);
        return false;
    }
    if (!hasSession) {
        if (document.getElementById('port') && typeof showPortalLogin === 'function') {
            showPortalLogin('Please login to publish CVE records.');
            setPortalSidebarState(true);
        } else {
            cveAlert('CVE Services login required', 'Please login to publish CVE records.');
        }
        return false;
    }
    return true;
}

async function cveSubmitDocToPortal(doc) {
    var j = cvePreparePublishDoc(doc);
    if (!j || !j.cveMetadata || !j.cveMetadata.cveId) {
        throw new Error('Missing cveMetadata.cveId');
    }
    var cveId = j.cveMetadata.cveId;
    var cveState = j.cveMetadata.state == 'REJECTED' ? 'REJECTED' : 'PUBLISHED';
    var cnaContainer = (j.containers && j.containers.cna) ? j.containers.cna : {};
    var latestId = await csClient.getCveId(cveId);
    var currentState = latestId && latestId.state;
    var ret = null;
    if (cveState == 'REJECTED') {
        // RESERVED -> REJECTED is a create (POST); rejecting a published record or
        // updating an already-rejected one is an update (PUT).
        if (currentState == 'RESERVED') {
            ret = await csClient.createRejectedCve(cveId, { cnaContainer: cnaContainer });
        } else {
            ret = await csClient.updateRejectedCve(cveId, { cnaContainer: cnaContainer });
        }
    } else {
        // Publishing: only an already-PUBLISHED record is updated (PUT). A RESERVED
        // OR REJECTED record is first published via create (POST) — this is #195:
        // moving a Rejected record to Published previously hit updateCve and errored.
        if (currentState == 'PUBLISHED') {
            ret = await csClient.updateCve(cveId, { cnaContainer: cnaContainer });
        } else {
            ret = await csClient.createCve(cveId, { cnaContainer: cnaContainer });
        }
    }
    j.cveMetadata.state = cveState;
    return {
        response: ret,
        doc: j
    };
}

async function cvePublishItems(items, onStatus, options) {
    var docs = Array.isArray(items) ? items : [];
    var notify = typeof onStatus === 'function' ? onStatus : function () { };
    var opts = options || {};
    var summary = {
        total: docs.length,
        published: 0,
        failed: 0,
        skipped: 0
    };
    if (docs.length == 0) {
        return summary;
    }
    var hasSession = await cveEnsurePublishSession();
    if (!hasSession) {
        summary.skipped = docs.length;
        docs.forEach(function (entry) {
            notify(entry, 'skipped', 'No active CVE Services session');
        });
        return summary;
    }
    for (var i = 0; i < docs.length; i++) {
        var entry = docs[i];
        var doc = entry ? entry.doc : null;
        var id = entry && entry.id ? entry.id : (doc && doc.cveMetadata ? doc.cveMetadata.cveId : null);
        if (!doc || !id) {
            summary.skipped++;
            notify(entry, 'skipped', 'Missing draft document');
            continue;
        }
        notify(entry, 'publishing', 'Publishing');
        try {
            var publishResult = await cveSubmitDocToPortal(doc);
            var ret = publishResult ? publishResult.response : null;
            if (ret == null) {
                throw new Error('No response from CVE Services. Please try again.');
            }
            summary.published++;
            var publishMessage = ret && ret.message ? ret.message : ('Successfully submitted ' + id);
            notify(entry, 'published', publishMessage, ret);
            if (opts.removeDrafts && typeof draftsCache !== 'undefined' && draftsCache && draftsCache.remove) {
                draftsCache.cancelSave();
                await draftsCache.remove(id);
            }
        } catch (e) {
            summary.failed++;
            notify(entry, 'failed', cvePublishErrorMessage(e), e);
        }
    }
    return summary;
}

async function cvePost() {
    var postFeedback = new feedback(document.getElementById('post1'), 'text', 'Posting...');
    try {
        var vr = filterADP(docEditor.validation_results);
        if (!(vr && vr.length == 0)) {
            cveAlert('Please fill the required fields');
            return;
        }
        if (!(await cveEnsurePublishSession())) {
            return;
        }
        /*if (save != undefined) {
            await save();
        }*/
        try {
            //if (csCache.portalType === 'test') {
                //console.log('uploading...');
                var j = await mainTabGroup.getValue();
                /*var pts = j.containers.cna.problemTypes;
                if(pts && pts.length == 1 && pts[0].descriptions && pts[0].descriptions[0].description == undefined) {
                    delete j.containers.cna.problemTypes;
                } 
                var ims = j.containers.cna.impacts;
                if(ims && ims.length == 1 && ims[0].descriptions && ims[0].descriptions[0].value == undefined) {
                    delete j.containers.cna.impacts;
                }*/
                var ret = null;
                var publishErrorShown = false;
                try {
                    var publishResult = await cveSubmitDocToPortal(j);
                    j = publishResult.doc;
                    ret = publishResult.response;
                } catch (e) {
                    //console.log('Got error');
                    //console.log(e);
                    console.error('Error publishing CVE record:', e);
                    if (e && e.error) {
                        if (typeof infoMsg !== 'undefined' && infoMsg) {
                            infoMsg.innerText = "";
                        }
                        if (e.details && e.details.errors && e.details.errors.length > 0) {
                            if (typeof showJSONerrors === 'function') {
                                showJSONerrors(e.details.errors.map(
                                    a => {
                                        return ({
                                            path: transatePath(a.instancePath),
                                            message: a.message
                                        });
                                    }
                                ));
                            } else {
                                await cveShowError(e);
                            }
                        } else {
                            await cveShowError(e);
                        }
                    } else {
                        cveAlert("Error publishing CVE", cvePublishErrorMessage(e));
                    }
                    publishErrorShown = true;
                }
                //console.log(ret);
                if (ret != null) {
                    var publishMessage = ret.message ? ret.message : "Successfully submitted " + j.cveMetadata.cveId;
                    cveAlert("CVE Record is Published", publishMessage, 10000);
                    var a = document.createElement('a');
                    a.setAttribute('href', (csCache.portalType == 'test'? 'https://test.cve.org/cverecord?id=' :  'https://www.cve.org/cverecord?id=')+j.cveMetadata.cveId);
                    a.setAttribute('target', '_blank');
                    a.innerText = j.cveMetadata.cveId;
                    if (typeof infoMsg !== 'undefined' && infoMsg) {
                        infoMsg.innerText = '';
                        infoMsg.appendChild(a);
                    }
                    if (typeof hideJSONerrors === 'function') {
                        hideJSONerrors();
                    }
                    if (typeof draftsCache !== 'undefined' && draftsCache && draftsCache.remove) {
                        draftsCache.cancelSave();
                        await draftsCache.remove(j.cveMetadata.cveId);
                    }
                } else if (!publishErrorShown) {
                    cveAlert("Error publishing CVE", "No response from CVE Services. Please try again.");
                }
            //} else {
            //    showAlert('CVE posting is not currently supported by production CVE services! Try Logging to Test Portal instance');
            //}
        } catch (e) {
            portalErrorHandler(e);
        }
    } finally {
        postFeedback.cancel();
    }
}

function postADPSetButtonMessage(button, message, isError) {
    if (!button || !button.parentNode || !message) {
        return;
    }
    var msgNode = button._postAdpMsgNode;
    if (!msgNode || !msgNode.parentNode) {
        msgNode = document.createElement('small');
        msgNode.className = 'lbl sml bor vgi-info rnd shd wht';
        msgNode.style.marginLeft = '0.5em';
        button.insertAdjacentElement('afterend', msgNode);
        button._postAdpMsgNode = msgNode;
    }
    msgNode.innerText = message;
    if (isError) {
        msgNode.classList.add('tred');
    } else {
        msgNode.classList.remove('tred');
    }
    if (button._postAdpMsgTimer) {
        clearTimeout(button._postAdpMsgTimer);
    }
    button._postAdpMsgTimer = setTimeout(function () {
        if (msgNode && msgNode.parentNode) {
            msgNode.parentNode.removeChild(msgNode);
        }
        button._postAdpMsgNode = null;
        button._postAdpMsgTimer = null;
    }, 15000);
}

async function postADP(orgID, button) {
    var postFeedback = button ? new feedback(button, 'text', 'Posting ...') : null;
    try {
        var currentOrgId = csCache && csCache.orgInfo ? csCache.orgInfo.UUID : null;
        if (!currentOrgId) {
            csCache.orgInfo = await csClient.getOrgInfo();
            currentOrgId = csCache.orgInfo ? csCache.orgInfo.UUID : null;
        }
        if (currentOrgId != orgID && orgID != '00000000-0000-4000-9000-000000000000') {
            cveAlert('This ADP information is not from Current CNA');
            return;
        }
        var j = await mainTabGroup.getValue();
        var cveId = j && j.cveMetadata ? j.cveMetadata.cveId : null;
        var adp = j && j.containers && Array.isArray(j.containers.adp) ? j.containers.adp : [];
        var matches = adp.filter(function (a) {
            return a && a.providerMetadata && a.providerMetadata.orgId == orgID;
        });
        if (matches.length > 1) {
            cveAlert('Error posting ADP', 'Multiple ADP information found for this CNA. Delete extras and try again.');
            return;
        }
        if (matches.length == 1) {
            if (!(await cveEnsurePublishSession())) {
                return;
            }
            var ret = await csClient.updateAdp(cveId, { adpContainer: matches[0] });
            postADPSetButtonMessage(button, (ret && ret.message) ? ret.message : 'ADP information posted.', false);
        }
    } catch (e) {
        var errorMessage = cvePublishErrorMessage(e);
        cveAlert('Error posting ADP', errorMessage);
        postADPSetButtonMessage(button, errorMessage, true);
    } finally {
        if (postFeedback) {
            postFeedback.cancel();
        }
    }
}

function cveTeamGetRowById(cveId) {
    if (!cveId) {
        return null;
    }
    var rowById = document.getElementById('vgListItem' + cveId);
    if (rowById) {
        return rowById;
    }
    var checks = document.querySelectorAll('#vgListTable .rowCheck');
    for (var i = 0; i < checks.length; i++) {
        if (checks[i].value == cveId) {
            return checks[i].closest('tr');
        }
    }
    return null;
}

function cveTeamGetStatusNode(cveId, createIfMissing) {
    var row = cveTeamGetRowById(cveId);
    if (!row) {
        return null;
    }
    var titleCell = row.querySelector('td.title, td.Title, td.TITLE');
    if (!titleCell) {
        var cells = row.querySelectorAll('td');
        if (cells.length > 0) {
            var logicalTitleIndex = row.querySelector('td.rowCheckLabel') ? 2 : 1;
            if (cells.length > logicalTitleIndex) {
                titleCell = cells[logicalTitleIndex];
            }
        }
    }
    if (!titleCell) {
        return null;
    }
    var statusNode = titleCell.querySelector('.teamPublishState');
    if (!statusNode && createIfMissing) {
        statusNode = document.createElement('small');
        statusNode.className = 'teamPublishState block sml';
        titleCell.appendChild(statusNode);
    }
    return statusNode;
}

function cveTeamSetRowStatus(cveId, text, isError) {
    var statusNode = cveTeamGetStatusNode(cveId, !!text);
    if (!statusNode) {
        return;
    }
    if (!text) {
        statusNode.remove();
        return;
    }
    statusNode.innerText = text;
    if (isError) {
        statusNode.classList.add('tred');
    } else {
        statusNode.classList.remove('tred');
    }
}

var cveDraftPublishEntries = [];
var cveDraftPublishStatusMap = {};
var cveDraftPublishRetainedRowsMap = {};
var cveDraftPublishTableSorter = null;

function cveDraftExtractTitle(doc) {
    if (!doc || !doc.containers || !doc.containers.cna) {
        return '';
    }
    var cna = doc.containers.cna;
    if (cna.title) {
        return String(cna.title);
    }
    if (typeof getBestTitle === 'function') {
        try {
            return String(getBestTitle(cna) || '');
        } catch (e) {
            // ignore and continue with fallback
        }
    }
    if (Array.isArray(cna.descriptions)) {
        var desc = cna.descriptions.find(function (d) {
            return d && d.value && (!d.lang || d.lang == 'en');
        });
        if (desc && desc.value) {
            return String(desc.value);
        }
    }
    return '';
}

function cveDraftExtractCvss(doc) {
    if (!doc || !doc.containers || !doc.containers.cna || !Array.isArray(doc.containers.cna.metrics)) {
        return '';
    }
    var metricKeys = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'];
    for (var i = 0; i < doc.containers.cna.metrics.length; i++) {
        var metric = doc.containers.cna.metrics[i];
        if (!metric || typeof metric !== 'object') {
            continue;
        }
        for (var j = 0; j < metricKeys.length; j++) {
            var key = metricKeys[j];
            var cvss = metric[key];
            if (!cvss || cvss.baseScore === undefined || cvss.baseScore === null || cvss.baseScore === '') {
                continue;
            }
            var score = Number(cvss.baseScore);
            if (isNaN(score)) {
                continue;
            }
            var severity = cvssjs.severityLevel(score);
            var scoreText = String(cvss.baseScore);
            return '<b class="tag CVSS ' + severity + '">' + scoreText + '</b>';
        }
    }
    return '';
}

function cveDraftCanPublish(entry) {
    if (!entry || !entry.doc || !entry.id) {
        return false;
    }
    if ((typeof entry.errorCount === 'number' ? entry.errorCount : 0) !== 0) {
        return false;
    }
    return !!(entry.doc.cveMetadata && entry.doc.cveMetadata.cveId);
}

function cveDraftPublishSetStatus(entryId, text, isError) {
    if (!text) {
        delete cveDraftPublishStatusMap[entryId];
    } else {
        cveDraftPublishStatusMap[entryId] = {
            text: text,
            isError: !!isError
        };
    }
    var titleCell = document.getElementById('draftPublishTitle-' + entryId);
    if (!titleCell) {
        return;
    }
    var statusNode = titleCell.querySelector('.draftPublishState');
    if (!statusNode && text) {
        statusNode = document.createElement('small');
        statusNode.className = 'draftPublishState block sml';
        titleCell.appendChild(statusNode);
    }
    if (!statusNode) {
        return;
    }
    if (!text) {
        statusNode.remove();
        return;
    }
    var safeText = String(text).replace(/[&<>"']/g, function (ch) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[ch];
    });
    safeText = safeText.replace(/CVE-\d{4}-\d{4,12}/gi, function (idText) {
        var cveId = idText.toUpperCase();
        return '<a href="https://vulnogram.org/seaview/?' + encodeURIComponent(cveId) + '" target="_blank" rel="noopener noreferrer">' + cveId + '</a>';
    });
    statusNode.innerHTML = safeText;
    if (isError) {
        statusNode.classList.add('tred');
    } else {
        statusNode.classList.remove('tred');
    }
}

function cveDraftPublishSetSummary(text, isError) {
    var msg = document.getElementById('draftPublishStatus');
    if (!msg) {
        return;
    }
    msg.innerText = text || '';
    if (isError) {
        msg.classList.add('tred');
    } else {
        msg.classList.remove('tred');
    }
}

function cveDraftPublishToggleAll(checkAll) {
    var rows = document.querySelectorAll('#draftPublishRows input[name="draftPublishSelection"]');
    rows.forEach(function (el) {
        if (!el.disabled) {
            el.checked = !!checkAll;
        }
    });
}

// #307: clone a draft into a new CVE, pre-filled but without the CVE ID.
function cveCloneDraft(entry) {
    if (!entry || !entry.doc) { return; }
    var clone = cveCloneDoc(entry.doc);
    if (clone && clone.cveMetadata) {
        delete clone.cveMetadata.cveId;
    }
    var dialog = document.getElementById('draftPublishDialog');
    if (dialog && dialog.open) { dialog.close(); }
    if (typeof draftsUi !== 'undefined' && draftsUi && draftsUi.toggle) {
        draftsUi.toggle.checked = true;
    }
    if (typeof loadJSON === 'function') {
        var edOpts = (typeof getEditorOptionsForDocValue === 'function') ? getEditorOptionsForDocValue(clone) : undefined;
        loadJSON(clone, undefined, 'Cloned from ' + entry.id + ' — assign a new CVE ID and save', edOpts);
    }
}

async function cveRefreshDraftPublishDialog() {
    if (!soloMode) {
        return;
    }
    var tbody = document.getElementById('draftPublishRows');
    if (!tbody) {
        return;
    }
    cveDraftPublishSetSummary('Loading drafts...');
    try {
        var entries = await draftsCache.getAll();
        entries = (entries || []).filter(function (entry) {
            return entry && entry.id && entry.doc;
        });
        entries.sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0); });
        cveDraftPublishEntries = entries;
        var entryById = {};
        entries.forEach(function (entry) {
            entryById[entry.id] = true;
        });
        var retainedEntries = Object.keys(cveDraftPublishRetainedRowsMap).map(function (id) {
            return cveDraftPublishRetainedRowsMap[id];
        }).filter(function (entry) {
            return entry && entry.id && !entryById[entry.id];
        });
        retainedEntries.sort(function (a, b) { return (b.updatedAt || 0) - (a.updatedAt || 0); });
        var allEntries = entries.concat(retainedEntries);
        var nextStatusMap = {};
        allEntries.forEach(function (entry) {
            if (entry && entry.id && cveDraftPublishStatusMap[entry.id]) {
                nextStatusMap[entry.id] = cveDraftPublishStatusMap[entry.id];
            }
        });
        cveDraftPublishStatusMap = nextStatusMap;
        tbody.textContent = '';
        if (allEntries.length == 0) {
            var emptyRow = document.createElement('tr');
            var emptyCell = document.createElement('td');
            emptyCell.colSpan = 7;
            emptyCell.innerText = 'No drafts found in local cache.';
            emptyRow.appendChild(emptyCell);
            tbody.appendChild(emptyRow);
            var emptyTable = document.getElementById('draftPublishTable');
            if (!cveDraftPublishTableSorter) {
                cveDraftPublishTableSorter = new Tablesort(emptyTable);
            } else {
                cveDraftPublishTableSorter.refresh();
            }
            cveDraftPublishSetSummary('No drafts found.');
            return;
        }
        var readyCount = 0;
        allEntries.forEach(function (entry) {
            var isRetainedPublished = entry.retainedPublished === true;
            var warningCount = isRetainedPublished ? 0 : (typeof entry.errorCount === 'number' ? entry.errorCount : 0);
            var canPublish = !isRetainedPublished && cveDraftCanPublish(entry);
            if (canPublish) {
                readyCount++;
            }
            var tr = document.createElement('tr');
            if (warningCount > 0) {
                tr.classList.add('dis');
            }

            var tdSelect = document.createElement('td');
            var cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.name = 'draftPublishSelection';
            cb.value = entry.id;
            cb.disabled = !canPublish;
            cb.checked = canPublish;
            tdSelect.appendChild(cb);
            tr.appendChild(tdSelect);

            var tdId = document.createElement('td');
            var idLink = document.createElement('a');
            idLink.className = 'lbl';
            idLink.innerText = entry.id;
            if (isRetainedPublished) {
                idLink.href = 'https://vulnogram.org/seaview/?' + encodeURIComponent(entry.id);
                idLink.target = '_blank';
                idLink.rel = 'noopener noreferrer';
                idLink.title = 'Open published CVE ' + entry.id + ' in seaview';
            } else {
                idLink.href = '#';
                idLink.title = 'Open draft ' + entry.id;
                idLink.addEventListener('click', function (e) {
                    e.preventDefault();
                    idLink.closest('dialog').close();
                    draftsUi.toggle.checked = true;
                    loadDraftFromCache(entry.id, false);
                });
            }
            tdId.appendChild(idLink);
            var warningBadge = document.createElement('span');
            warningBadge.className = 'bdg';
            warningBadge.title = String(warningCount);
            warningBadge.innerText = String(warningCount);
            tdId.appendChild(document.createTextNode(' '));
            tdId.appendChild(warningBadge);
            tr.appendChild(tdId);

            var tdTitle = document.createElement('td');
            tdTitle.id = 'draftPublishTitle-' + entry.id;
            var title = cveDraftExtractTitle(entry.doc);
            tdTitle.innerText = title || '';
            if (title) {
                tdTitle.title = title;
            }
            var status = cveDraftPublishStatusMap[entry.id];
            if (status && status.text) {
                var titleStatus = document.createElement('small');
                titleStatus.className = 'draftPublishState block sml';
                var titleSafeText = String(status.text).replace(/[&<>"']/g, function (ch) {
                    return {
                        '&': '&amp;',
                        '<': '&lt;',
                        '>': '&gt;',
                        '"': '&quot;',
                        "'": '&#39;'
                    }[ch];
                });
                titleSafeText = titleSafeText.replace(/CVE-\d{4}-\d{4,12}/gi, function (idText) {
                    var cveId = idText.toUpperCase();
                    return '<a href="https://vulnogram.org/seaview/?' + encodeURIComponent(cveId) + '" target="_blank" rel="noopener noreferrer">' + cveId + '</a>';
                });
                titleStatus.innerHTML = titleSafeText;
                if (status.isError) {
                    titleStatus.classList.add('tred');
                }
                tdTitle.appendChild(titleStatus);
            }
            tr.appendChild(tdTitle);

            var tdCvss = document.createElement('td');
            tdCvss.innerHTML = cveDraftExtractCvss(entry.doc);
            tr.appendChild(tdCvss);

            var tdPublicOn = document.createElement('td');
            var publicOn = entry && entry.doc && entry.doc.containers && entry.doc.containers.cna ? entry.doc.containers.cna.datePublic : null;
            if (publicOn) {
                var publicOnDate = new Date(publicOn);
                if (!isNaN(publicOnDate.getTime())) {
                    tdPublicOn.setAttribute('data-sort', String(publicOnDate.getTime()));
                    if (typeof textUtil !== 'undefined' && textUtil && typeof textUtil.formatFriendlyDate === 'function') {
                        tdPublicOn.innerText = textUtil.formatFriendlyDate(publicOnDate);
                    } else {
                        tdPublicOn.innerText = publicOnDate.toISOString();
                    }
                }
            }
            tr.appendChild(tdPublicOn);

            var tdTime = document.createElement('td');
            if (entry.updatedAt) {
                var updatedAt = new Date(entry.updatedAt);
                tdTime.setAttribute('data-sort', String(updatedAt.getTime()));
                if (typeof textUtil !== 'undefined' && textUtil && typeof textUtil.formatFriendlyDate === 'function') {
                    tdTime.innerText = textUtil.formatFriendlyDate(updatedAt);
                } else {
                    tdTime.innerText = updatedAt.toISOString();
                }
            }
            tr.appendChild(tdTime);

            var tdActions = document.createElement('td');
            tdActions.style.textAlign = 'right';
            if (!isRetainedPublished) {
                var cloneBtn = document.createElement('button');
                cloneBtn.type = 'button';
                cloneBtn.className = 'sbn fbn';
                cloneBtn.innerText = 'Clone';
                cloneBtn.title = 'Clone ' + entry.id + ' into a new CVE (without the ID)';
                cloneBtn.setAttribute('aria-label', 'Clone draft ' + entry.id);
                cloneBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    cveCloneDraft(entry);
                });
                tdActions.appendChild(cloneBtn);
                tdActions.appendChild(document.createTextNode(' '));
                var deleteBtn = document.createElement('button');
                deleteBtn.type = 'button';
                deleteBtn.className = 'sbn fbn vgi-del';
                deleteBtn.title = 'Delete draft ' + entry.id;
                deleteBtn.setAttribute('aria-label', 'Delete draft ' + entry.id);
                deleteBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    confirmDialog('Delete draft ' + entry.id + '?', 'This removes the local draft and cannot be undone.').then(function (confirmed) {
                        if (!confirmed) return;
                        cveDraftPublishSetStatus(entry.id, '');
                        cveDraftPublishSetSummary('Deleting draft ' + entry.id + '...');
                        draftsCache.cancelSave();
                        return Promise.resolve(draftsCache.remove(entry.id)).then(function () {
                            return cveRefreshDraftPublishDialog();
                        }).then(function () {
                            cveDraftPublishSetSummary('Deleted draft ' + entry.id + '.');
                        }).catch(function (err) {
                            cveDraftPublishSetSummary(cvePublishErrorMessage(err), true);
                        });
                    });
                });
                tdActions.appendChild(deleteBtn);
            }
            tr.appendChild(tdActions);
            tbody.appendChild(tr);
        });
        var draftTable = document.getElementById('draftPublishTable');
        if (!cveDraftPublishTableSorter) {
            cveDraftPublishTableSorter = new Tablesort(draftTable);
        } else {
            cveDraftPublishTableSorter.refresh();
        }
        var summaryMessage = '';
        if (entries.length > 0) {
            summaryMessage = 'Found ' + entries.length + ' drafts. Ready to publish: ' + readyCount + '.' + (readyCount < entries.length ? ' Fix errors to publish the remaining.' : '');
        }
        if (retainedEntries.length > 0) {
            summaryMessage += (summaryMessage ? ' ' : '') + 'Published references: ' + retainedEntries.length + '.';
        }
        cveDraftPublishSetSummary(summaryMessage);
    } catch (e) {
        cveDraftPublishSetSummary(cvePublishErrorMessage(e), true);
    }
}

async function cveOpenDraftPublishDialog(event) {
    if (event && event.preventDefault) {
        event.preventDefault();
    }
    if (!soloMode) {
        return false;
    }
    var dialog = document.getElementById('draftPublishDialog');
    if (!dialog) {
        return false;
    }
    await cveRefreshDraftPublishDialog();
    if (!dialog.open) {
        dialog.showModal();
    }
    return false;
}

async function cvePublishSelectedDrafts(event) {
    if (event && event.preventDefault) {
        event.preventDefault();
    }
    if (!soloMode) {
        return false;
    }
    var selected = Array.from(document.querySelectorAll('#draftPublishRows input[name="draftPublishSelection"]:checked'))
        .map(function (el) { return el.value; });
    if (selected.length == 0) {
        cveDraftPublishSetSummary('Select one or more drafts with 0 errors.', true);
        return false;
    }
    var selectedSet = new Set(selected);
    var items = cveDraftPublishEntries.filter(function (entry) {
        return selectedSet.has(entry.id) && cveDraftCanPublish(entry);
    }).map(function (entry) {
        return { id: entry.id, doc: entry.doc };
    });
    if (items.length == 0) {
        cveDraftPublishSetSummary('No publishable drafts selected.', true);
        return false;
    }
    cveDraftPublishSetSummary('Publishing ' + items.length + ' draft(s)...');
    var summary = await cvePublishItems(items, function (entry, state, message) {
        if (!entry || !entry.id) {
            return;
        }
        if (state == 'publishing') {
            cveDraftPublishSetStatus(entry.id, 'Publishing...');
        } else if (state == 'published') {
            cveDraftPublishRetainedRowsMap[entry.id] = {
                id: entry.id,
                doc: entry.doc,
                errorCount: 0,
                updatedAt: Date.now(),
                retainedPublished: true
            };
            var publishStatusMessage = message || ('Successfully submitted ' + entry.id);
            if (!/CVE-\d{4}-\d{4,12}/i.test(publishStatusMessage)) {
                publishStatusMessage += ' ' + entry.id;
            }
            cveDraftPublishSetStatus(entry.id, publishStatusMessage);
        } else if (state == 'failed') {
            cveDraftPublishSetStatus(entry.id, message, true);
        } else if (state == 'skipped') {
            cveDraftPublishSetStatus(entry.id, message, true);
        }
    }, { removeDrafts: true });
    await cveRefreshDraftPublishDialog();
    if (summary.skipped == summary.total && summary.total > 0 && summary.failed == 0 && summary.published == 0) {
        cveDraftPublishSetSummary('Login required to publish selected drafts.', true);
    } else if (summary.failed > 0) {
        cveDraftPublishSetSummary('Published ' + summary.published + ' of ' + summary.total + '. Failed: ' + summary.failed + '.', true);
    } else {
        cveDraftPublishSetSummary('Successfully published ' + summary.published + ' draft(s).');
    }
    return false;
}

async function cveReserveAndRender(yearOffset, number) {
    try {
        var r = await cveReserve(yearOffset, number);
        var m = document.getElementById("cveStatusMessage");
        if (m && r && r.length > 0) {
            m.innerText = "Got " + r.map(x => x.cve_id).join(', ');
        } else {
            m.innerText = "Failed to get a CVE ID";
        }
        var cveForm = document.getElementById("cvePortalFilter");
        if (cveForm) {
            if (cveForm.fstate) {
                cveForm.fstate.value = 'RESERVED';
            }
            var reservedState = document.getElementById("chkres");
            if (reservedState) {
                reservedState.checked = true;
            }
            if (cveForm.y) {
                cveForm.y.value = String(currentYear + (yearOffset ? yearOffset : 0));
            }
            cveForm.page = 0;
        }
        await cveGetList();
        return r;
    } catch (e) {
        portalErrorHandler(e);
    }
}
