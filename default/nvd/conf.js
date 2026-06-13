// NVD records are stored in the native NVD CVE API 2.0 shape:
//   { cve: { id, published, lastModified, descriptions[], metrics{cvssMetricV31[],..},
//            weaknesses[], configurations[], ... } }
// imported by scripts/nvdimport.js. The helpers below adapt the facet/chart
// aggregation to the 2.0 layout, where CVSS lives in arrays (Primary + Secondary)
// and affected products are CPE strings rather than a vendor list.

// Extract `field` from the Primary cvssMetricV31 entry, falling back to the first
// entry; null-safe for older CVEs that only carry cvssMetricV2 (no V31 array).
function primaryV31(field) {
    return {
        $let: {
            vars: {
                primary: {
                    $first: {
                        $filter: {
                            input: { $ifNull: ['$cve.metrics.cvssMetricV31', []] },
                            cond: { $eq: ['$$this.type', 'Primary'] }
                        }
                    }
                },
                any: { $first: { $ifNull: ['$cve.metrics.cvssMetricV31', []] } }
            },
            in: { $ifNull: ['$$primary.cvssData.' + field, '$$any.cvssData.' + field] }
        }
    };
}

// Chart pipeline that reduces the cvssMetricV31 array to one scalar before counting.
function v31ChartPipeline(field) {
    return [
        { $project: { v: primaryV31(field) } },
        { $sortByCount: '$v' }
    ];
}

module.exports = {
conf:{
    title: 'National Vulnerability Database',
    readonly: true,
    name: 'NVD',
    disableDrafts: true,
    class: 'vgi-data',
    collectionName: 'nvds'
},
facet: {
    ID: {
        path: 'cve.id',
        regex: 'CVE-[0-9]{4}-[0-9]{4,10}',
        class: 'nobr'
    },
    cvss: {
        path: 'cve.metrics.cvssMetricV31.cvssData.baseScore',
        //chart: true,
        //hideColumn: true
    },
    severity: {
        path: 'cve.metrics.cvssMetricV31.cvssData.baseSeverity',
        chart: true,
        hideColumn: true,
        pipeline: v31ChartPipeline('baseSeverity')
    },
    AV: {
        path: 'cve.metrics.cvssMetricV31.cvssData.attackVector',
        chart: true,
        pipeline: v31ChartPipeline('attackVector')
    },
    PR: {
        path: 'cve.metrics.cvssMetricV31.cvssData.privilegesRequired',
        chart: true,
        pipeline: v31ChartPipeline('privilegesRequired')
    },
    C: {
        path: 'cve.metrics.cvssMetricV31.cvssData.confidentialityImpact',
        chart: true,
        pipeline: v31ChartPipeline('confidentialityImpact')
    },
    I: {
        path: 'cve.metrics.cvssMetricV31.cvssData.integrityImpact',
        chart: true,
        pipeline: v31ChartPipeline('integrityImpact')
    },
    A: {
        // 2.0 field is availabilityImpact (the legacy config had a typo: avilabilityVector)
        path: 'cve.metrics.cvssMetricV31.cvssData.availabilityImpact',
        chart: true,
        pipeline: v31ChartPipeline('availabilityImpact')
    },
    date: {
        path: 'cve.published',
        sortDefault: '-date'
    },
    type: {
        path: 'cve.weaknesses.description.value',
        //chart: true
    },
    vendor: {
        // Derived from the CPE 2.3 criteria string cpe:2.3:<part>:<vendor>:<product>:...
        // index 3 is the vendor (0=cpe, 1=2.3, 2=part, 3=vendor, 4=product).
        path: 'cve.configurations.nodes.cpeMatch.criteria',
        chart: true,
        hideColumn: true,
        pipeline: [
            { $unwind: "$cve.configurations" },
            { $unwind: "$cve.configurations.nodes" },
            { $unwind: "$cve.configurations.nodes.cpeMatch" },
            {
                $project: {
                    vendor: {
                        $arrayElemAt: [
                            { $split: ["$cve.configurations.nodes.cpeMatch.criteria", ":"] },
                            3
                        ]
                    }
                }
            }, {
                $sortByCount: "$vendor"
            }
        ]
    },
   /* product: {
        path: 'cve.configurations.nodes.cpeMatch.criteria',
        chart: true,
        hideColumn: true,
        pipeline: [
            { $unwind: "$cve.configurations" },
            { $unwind: "$cve.configurations.nodes" },
            { $unwind: "$cve.configurations.nodes.cpeMatch" },
            {
                $project: {
                    product: {
                        $arrayElemAt: [
                            { $split: ["$cve.configurations.nodes.cpeMatch.criteria", ":"] },
                            4
                        ]
                    }
                }
            }, {
                 $sortByCount: "$product"
            }
        ]
    },*/
    description: {
        path: 'cve.descriptions.value',
        class: 'sgl'
    }
}
}
