defaultTabs.sourceTab.getValue = function () {
    var res = JSON.parse(sourceEditor.getSession().getValue());
    res = cveFixForVulnogram(res);
    /* The Source view hides CNA_private (private internal-workflow data); re-attach the
       copy stashed by sourceTab.setValue so editing/saving from Source never drops it. */
    if (defaultTabs.sourceTab._cnaPrivate !== undefined && res && typeof res === 'object') {
        res.CNA_private = defaultTabs.sourceTab._cnaPrivate;
    }
    return res;
};
