#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');
const { loadKeys, readMec, writeMec, encodingProfile } = require('./lib/mec.cjs');
const { makeDxf } = require('./lib/dxf.cjs');

const help = `Usage:
  node --openssl-legacy-provider convert.cjs --to dxf|8.2|9.2 --out PATH INPUT
    (--key-file PATH | --lantek-dir PATH) [--target-reference FILE]

INPUT can be a .mec file or a directory. An output directory is created with
the same folder structure. Existing files are never replaced.
For MEC output from an installation folder, select a known-good MEC file
of the destination version with --target-reference.
`;

function readArguments(args) {
    const { values, positionals } = parseArgs({
        args,
        allowPositionals: true,
        options: {
            to: { type: 'string' },
            out: { type: 'string' },
            'key-file': { type: 'string' },
            'lantek-dir': { type: 'string' },
            'target-reference': { type: 'string' },
            help: { type: 'boolean', short: 'h' },
        },
    });
    if (values.help) return null;
    if (positionals.length !== 1 || !values.out || !['dxf', '8.2', '9.2'].includes(values.to)) {
        throw new Error('Provide one input, --out, and --to dxf, 8.2 or 9.2. See --help.');
    }
    if (Boolean(values['key-file']) === Boolean(values['lantek-dir'])) {
        throw new Error('Set either --key-file or --lantek-dir.');
    }
    if (values.to === 'dxf' && values['target-reference']) {
        throw new Error('--target-reference is only used for MEC output.');
    }
    return {
        source: path.resolve(positionals[0]),
        target: path.resolve(values.out),
        to: values.to,
        keyFile: values['key-file'],
        lantekDir: values['lantek-dir'],
        reference: values['target-reference'],
    };
}

function destinationPath(name) {
    // Resolve existing parents to catch symlink aliases inside the source tree.
    if (fs.existsSync(name)) return fs.realpathSync(name);
    const parent = path.dirname(name);
    if (parent === name) return name;
    return path.join(destinationPath(parent), path.basename(name));
}

function isInside(parent, child) {
    const relative = path.relative(parent, child);
    return !relative || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
}

function convertOne(source, target, settings) {
    const decoded = readMec(fs.readFileSync(source), settings.keys, settings.memo);
    let data, diagnostics;
    if (settings.to === 'dxf') {
        const result = makeDxf(decoded.records, { version: decoded.version });
        data = result.dxf;
        diagnostics = result.diagnostics;
    } else {
        data = writeMec(decoded.records, settings.to, settings.profile);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data, { flag: 'wx' });
    for (const note of diagnostics ?? []) {
        console.error(`Note: ${source}: ${note}`);
    }
}

function convertTree(source, target, settings, counts) {
    fs.mkdirSync(target);
    for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
        const input = path.join(source, entry.name);
        if (entry.isDirectory()) {
            convertTree(input, path.join(target, entry.name), settings, counts);
        } else if (entry.isFile() && /\.mec$/i.test(entry.name)) {
            const filename = entry.name.slice(0, -4) + settings.extension;
            try {
                convertOne(input, path.join(target, filename), settings);
                counts.converted++;
            } catch (error) {
                counts.failed++;
                console.error(`Error: ${input}: ${error.message}`);
            }
        }
    }
}

function main(args) {
    const settings = readArguments(args);
    if (!settings) {
        process.stdout.write(help);
        return;
    }
    const source = fs.realpathSync(settings.source);
    const target = destinationPath(settings.target);
    const sourceStat = fs.statSync(source);
    if (!sourceStat.isDirectory() && (!sourceStat.isFile() || !/\.mec$/i.test(source))) {
        throw new Error('Input must be a MEC file or directory.');
    }
    if (sourceStat.isDirectory() && isInside(source, target)) {
        throw new Error('The output directory must be outside the input tree.');
    }
    if (fs.existsSync(target)) {
        throw new Error('Output already exists: ' + target);
    }

    settings.extension = settings.to === 'dxf' ? '.dxf' : '.mec';
    if (sourceStat.isFile() && path.extname(target).toLowerCase() !== settings.extension) {
        throw new Error('The output file extension must be ' + settings.extension);
    }
    settings.keys = loadKeys(settings);
    settings.memo = {};
    if (settings.to !== 'dxf') {
        const reference = settings.reference && fs.readFileSync(settings.reference);
        settings.profile = encodingProfile(settings.to, settings.keys, reference);
    }
    if (sourceStat.isFile()) {
        convertOne(source, target, settings);
        console.log('Converted 1 file.');
        return;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const counts = { converted: 0, failed: 0 };
    convertTree(source, target, settings, counts);
    console.log(`Converted ${counts.converted} file(s). Failed: ${counts.failed}.`);
    return counts.failed ? 1 : 0;
}

if (require.main === module) {
    try {
        process.exitCode = main(process.argv.slice(2)) ?? 0;
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}

module.exports = { main };
