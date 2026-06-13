#!/usr/bin/env node
// Copyright (c) 2018 Chandan B N. All rights reserved.
//
// Command-line front-end for the NVD sync engine in lib/nvdsync.js. Useful for
// the initial bulk backfill and for manual / one-off runs. The running Vulnogram
// app keeps NVD fresh on its own (see lib/nvdsync.js start() wired into app.js),
// so a cron job is NOT required.
//
// Usage:
//   node scripts/nvdimport.js --backfill [--year YYYY | --from YYYY --to YYYY | --all]
//   node scripts/nvdimport.js --update   [--since ISO8601] [--days N(<=120)]
//   node scripts/nvdimport.js --modified | --recent      # fast 8-day catch-up via mirror
//   node scripts/nvdimport.js --file <path[.json|.json.xz]>
//   node scripts/nvdimport.js --cve CVE-2021-44228
//   (global) --dry-run --batch N --limit N --no-index -h/--help
//
// Env:
//   NVD_API_KEY   optional NVD API key (raises the rate limit; recommended for --update)
//   MONGO_*       MongoDB connection (consumed via config/conf.js, same as the app)

require('dotenv').config();
const config = require('../config/conf');
const mongo = require('../lib/mongo');
const nvd = require('../lib/nvdsync');

function parseArgs(argv) {
    const opts = { mode: null, dryRun: false, batch: 1000, limit: Infinity, index: true, apiKey: process.env.NVD_API_KEY || '' };
    const a = argv.slice(2);
    for (let i = 0; i < a.length; i++) {
        switch (a[i]) {
            case '--backfill': opts.mode = 'backfill'; break;
            case '--update': opts.mode = 'update'; break;
            case '--modified': opts.mode = 'modified'; break;
            case '--recent': opts.mode = 'recent'; break;
            case '--file': opts.mode = 'file'; opts.file = a[++i]; break;
            case '--cve': opts.mode = 'cve'; opts.cve = a[++i]; break;
            case '--all': opts.all = true; break;
            case '--year': opts.year = Number(a[++i]); break;
            case '--from': opts.from = Number(a[++i]); break;
            case '--to': opts.to = Number(a[++i]); break;
            case '--since': opts.since = a[++i]; break;
            case '--days': opts.days = Number(a[++i]); break;
            case '--batch': opts.batch = Number(a[++i]) || 1000; break;
            case '--limit': opts.limit = Number(a[++i]) || Infinity; break;
            case '--no-index': opts.index = false; break;
            case '--dry-run': opts.dryRun = true; break;
            case '-h':
            case '--help': opts.mode = 'help'; break;
            default:
                console.error('Unknown argument: ' + a[i]);
                opts.mode = 'help';
        }
    }
    return opts;
}

function printHelp() {
    console.log([
        'Import NVD CVE data into the "' + nvd.COLLECTION + '" collection (native NVD API 2.0 shape).',
        'The running app syncs automatically; this CLI is for the initial backfill and manual runs.',
        '',
        'Modes:',
        '  --backfill [--year Y | --from Y --to Y | --all]   Bulk load from the fkie-cad mirror',
        '                                                    (default: every year ' + nvd.FIRST_YEAR + '..now)',
        '  --update   [--since ISO8601] [--days N(<=120)]    Incremental sync from the NVD API 2.0',
        '  --modified                                        Mirror feed: changed in the last 8 days',
        '  --recent                                          Mirror feed: added in the last 8 days',
        '  --file <path[.json|.json.xz]>                     Import a local NVD 2.0 / fkie-cad file',
        '  --cve CVE-XXXX-NNNN                               Fetch a single CVE from the NVD API',
        '',
        'Options:',
        '  --dry-run     Process and print a sample; do NOT connect to or write MongoDB',
        '  --batch N     bulkWrite batch size (default 1000)',
        '  --limit N     Stop after N records (debugging)',
        '  --no-index    Skip index creation',
        '  -h, --help    Show this help',
        '',
        'Examples:',
        '  node scripts/nvdimport.js --backfill              # full history via the mirror',
        '  node scripts/nvdimport.js --update                # catch up since the newest stored record',
        '  node scripts/nvdimport.js --cve CVE-2021-44228 --dry-run'
    ].join('\n'));
}

function dispatch(col, opts, stats) {
    switch (opts.mode) {
        case 'backfill': return nvd.backfill(col, opts, stats);
        case 'update': return nvd.syncUpdate(col, opts, stats);
        case 'modified': return nvd.syncFeed(col, opts, stats, 'CVE-modified');
        case 'recent': return nvd.syncFeed(col, opts, stats, 'CVE-recent');
        case 'file': return nvd.importFile(col, opts, stats);
        case 'cve': return nvd.importCve(col, opts, stats);
        default: return Promise.resolve();
    }
}

async function main() {
    const opts = parseArgs(process.argv);
    if (!opts.mode || opts.mode === 'help') {
        printHelp();
        process.exitCode = opts.mode === 'help' ? 0 : 1;
        return;
    }

    const stats = nvd.newStats();
    const started = Date.now();

    if (opts.dryRun) {
        console.log('[nvdimport] DRY RUN -', opts.mode, '- no MongoDB connection will be made.');
        await dispatch(null, opts, stats);
    } else {
        await mongo.connect(config.database);
        try {
            const col = mongo.getCollection(nvd.COLLECTION);
            if (opts.index) {
                await nvd.ensureIndexes(col);
            }
            await dispatch(col, opts, stats);
        } finally {
            await mongo.close();
        }
    }

    const secs = ((Date.now() - started) / 1000).toFixed(1);
    console.log('[nvdimport] done in', secs + 's -', nvd.summary(stats));
}

main().catch(function (err) {
    console.error('[nvdimport] fatal:', err && err.message ? err.message : err);
    mongo.close().catch(function () {}).finally(function () {
        process.exit(1);
    });
});
