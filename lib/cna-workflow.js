// Internal CNA workflow helpers: the nested CNA_private shape, the flat->nested
// normalize shim (so legacy drafts keep working), per-team stages, and
// capability-gated state-transition validation.

const rbac = require('./rbac');

const DEFAULT_STAGES = ['new', 'open', 'draft', 'review', 'waiting', 'pending', 'closed'];

// Target stages that need an elevated capability beyond cve.transition.
const DEFAULT_STAGE_CAPS = {
    review: rbac.CAPABILITIES.CVE_REVIEW,
    pending: rbac.CAPABILITIES.CVE_APPROVE
};

// Restructure a flat legacy CNA_private block into the nested (tabbed) shape.
// Idempotent: an already-nested block is returned unchanged.
function normalize(cna) {
    if (!cna || typeof cna !== 'object') {
        return cna;
    }
    if (cna.people || cna.triage || cna.dates || cna.checklist || cna.notes) {
        return cna; // already nested
    }
    var nested = { people: {}, triage: {}, dates: {}, checklist: {}, notes: {} };
    if (cna.owner !== undefined) nested.people.owner = cna.owner;
    if (cna.assignees !== undefined) nested.people.assignees = cna.assignees;
    if (cna.reviewers !== undefined) nested.people.reviewers = cna.reviewers;
    if (cna.approvers !== undefined) nested.people.approvers = cna.approvers;
    if (cna.state !== undefined) nested.triage.state = cna.state;
    if (cna.type !== undefined) nested.triage.type = cna.type;
    if (cna.priority !== undefined) nested.triage.priority = cna.priority;
    if (cna.severity !== undefined) nested.triage.severity = cna.severity;
    if (cna.labels !== undefined) nested.triage.labels = cna.labels;
    if (cna.publish !== undefined) nested.triage.publish = cna.publish;
    if (cna.due !== undefined) nested.dates.due = cna.due;
    if (cna.embargo !== undefined) nested.dates.embargo = cna.embargo;
    if (cna.notes !== undefined) nested.notes.notes = cna.notes;
    if (Array.isArray(cna.todo)) {
        nested.checklist.todo = cna.todo.map(function (t) {
            if (t && typeof t === 'object') { return t; }
            return { task: String(t == null ? '' : t), done: false };
        });
    }
    return nested;
}

// Read the workflow state from either the nested or flat shape.
function getState(cna) {
    if (!cna || typeof cna !== 'object') {
        return undefined;
    }
    if (cna.triage && cna.triage.state !== undefined) {
        return cna.triage.state;
    }
    return cna.state;
}

function teamStages(team) {
    if (team && team.settings && Array.isArray(team.settings.stages) && team.settings.stages.length) {
        return team.settings.stages;
    }
    return DEFAULT_STAGES.slice();
}

function stageCaps(team) {
    if (team && team.settings && team.settings.stageCaps && typeof team.settings.stageCaps === 'object') {
        return team.settings.stageCaps;
    }
    return DEFAULT_STAGE_CAPS;
}

// Validate a workflow state transition. Returns { ok, message }.
function validateTransition(user, doc, fromState, toState, team) {
    if (toState === undefined || fromState === toState) {
        return { ok: true };
    }
    var teamKey = doc && doc.team ? doc.team : undefined;
    var stages = teamStages(team);
    if (stages.indexOf(toState) < 0) {
        return { ok: false, message: 'Invalid workflow stage: ' + toState };
    }
    if (!rbac.can(user, rbac.CAPABILITIES.CVE_TRANSITION, { team: teamKey })) {
        return { ok: false, message: 'You do not have permission to change the workflow stage.' };
    }
    var needed = stageCaps(team)[toState];
    if (needed && !rbac.can(user, needed, { team: teamKey })) {
        return { ok: false, message: 'Moving to "' + toState + '" requires the ' + needed + ' capability.' };
    }
    return { ok: true };
}

module.exports = {
    DEFAULT_STAGES: DEFAULT_STAGES,
    DEFAULT_STAGE_CAPS: DEFAULT_STAGE_CAPS,
    normalize: normalize,
    getState: getState,
    teamStages: teamStages,
    stageCaps: stageCaps,
    validateTransition: validateTransition
};
