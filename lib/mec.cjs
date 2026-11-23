'use strict';

// MEC format and installation-file discovery are based on the MIT-licensed
// NestPro reader. Copyright (c) 2026 Kerf Labs. See LICENSE.
// https://github.com/KurfLabs/nestpro/blob/81bcd3bcdbf9298fad1c2f8c5bef1b591fdea7c4/app/src/formats/mec.rs

const fs = require('node:fs');
const path = require('node:path');
const { createCipheriv, createDecipheriv } = require('node:crypto');

const ZERO_IV = Buffer.alloc(8);
const READ_VERSIONS = new Set(['8.00', '8.1', '8.2', '9.2']);
const WRITE_VERSIONS = new Set(['8.2', '9.2']);
const keyStores = new WeakMap();
const profiles = new WeakMap();
const memoStores = new WeakMap();

function addCandidate(list, value) {
    if (!list.some(previous => previous.equals(value))) list.push(value);
}

function combineCandidates(preferred, candidates) {
    const byHex = new Map();
    for (const value of [...preferred, ...candidates]) {
        byHex.set(value.toString('hex'), value);
    }
    return [...byHex.values()];
}

function fileKeys(file) {
    const keys = { line: [], file: [], iv: [] };
    const names = new Map([['line-key', 'line'], ['file-key', 'file'], ['file-iv', 'iv']]);
    const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
    for (const [index, raw] of lines.entries()) {
        const line = raw.split('#', 1)[0].trim();
        if (!line) continue;
        const match = /^(line-key|file-key|file-iv)\s*=\s*([\da-f ]+)$/i.exec(line);
        const hex = match?.[2].replace(/ /g, '');
        if (hex?.length !== 32) {
            throw new Error(`Invalid MEC key configuration at line ${index + 1} (expected a known name and 32 hex digits).`);
        }
        addCandidate(keys[names.get(match[1].toLowerCase())], Buffer.from(hex, 'hex'));
    }
    return keys;
}

function installationCandidates(dir) {
    const candidates = new Map();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (!entry.isFile() || path.extname(entry.name).toLowerCase() !== '.dll') continue;
        let data;
        try {
            data = fs.readFileSync(path.join(dir, entry.name));
        } catch {
            continue;
        }
        // NestPro observes a 16-byte value written using four adjacent dword stores.
        for (let offset = 0; offset + 27 <= data.length; offset++) {
            const prefixed = data[offset] === 0x41;
            const start = offset + Number(prefixed);
            const base = data[start + 1];
            if (data[start] !== 0xc7 || base > 7 || base === 4 || base === 5) continue;
            const value = Buffer.alloc(16);
            data.copy(value, 0, start + 2, start + 6);
            let next = start + 6;
            let complete = true;
            for (let part = 1; part < 4; part++) {
                if ((prefixed && data[next++] !== 0x41) || next + 7 > data.length
                    || data[next] !== 0xc7 || data[next + 1] !== (0x40 | base)
                    || data[next + 2] !== part * 4) {
                    complete = false;
                    break;
                }
                data.copy(value, part * 4, next + 3, next + 7);
                next += 7;
            }
            if (complete) {
                candidates.set(value.toString('hex'), value);
                offset = next - 1;
            }
        }
    }
    if (!candidates.size) throw new Error('No MEC format candidates found in the supplied Lantek folder.');
    return [...candidates.values()];
}

function loadKeys({ keyFile, lantekDir } = {}) {
    if (!keyFile && !lantekDir) throw new Error('Supply a MEC key file or a compatible Lantek folder.');
    const explicit = keyFile ? fileKeys(keyFile) : { line: [], file: [], iv: [] };
    const candidates = lantekDir ? installationCandidates(lantekDir) : [];
    if (!candidates.length && !Object.values(explicit).some(values => values.length)) {
        throw new Error('The MEC key file contains no keys.');
    }
    const token = Object.freeze({});
    keyStores.set(token, {
        explicit,
        line: combineCandidates(explicit.line, candidates),
        file: combineCandidates(explicit.file, candidates),
        iv: combineCandidates(explicit.iv, candidates),
    });
    return token;
}

function getKeys(token) {
    const store = keyStores.get(token);
    if (!store) throw new TypeError('Expected keys from loadKeys().');
    return store;
}

function profileToken(fields) {
    const token = Object.freeze({});
    profiles.set(token, fields);
    return token;
}

function headerOf(buffer) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError('Expected a MEC Buffer.');
    const end = buffer.indexOf(10);
    const head = end >= 0 && end <= 32 ? buffer.subarray(0, end).toString('latin1') : '';
    const match = /^0 FILEMECLT (\d+\.\d+)(\r?)$/.exec(head);
    if (!match || !READ_VERSIONS.has(match[1])) throw new Error('Unsupported or missing FILEMECLT header.');
    return { version: match[1], headerEol: match[2] + '\n', body: buffer.subarray(end + 1) };
}

function withoutPadding(row) {
    let end = row.length;
    while (end > 0 && (row[end - 1] === 0x20 || row[end - 1] === 0)) end--;
    return row.subarray(0, end);
}

function validRecords(records) {
    let finished = false;
    let count = 0;
    for (const row of records) {
        const line = row.toString('latin1').trim();
        if (!line) continue;
        if (finished || !/^\d+(?:[ \t\v\f]|$)/.test(line)) return false;
        finished = line === '999';
        count++;
    }
    return finished && count > 1;
}

function blowfish(data, key, decrypt) {
    try {
        const cipher = (decrypt ? createDecipheriv : createCipheriv)('bf-cbc', key, ZERO_IV);
        cipher.setAutoPadding(false);
        return Buffer.concat([cipher.update(data), cipher.final()]);
    } catch (error) {
        if (error.code === 'ERR_OSSL_EVP_UNSUPPORTED') {
            throw new Error('Blowfish is unavailable. Start Node with --openssl-legacy-provider.');
        }
        throw error;
    }
}

function legacyRows(body) {
    const rows = body.toString('latin1').split(/\r?\n/).filter(Boolean);
    if (!rows.length || rows.some(row => row.length % 16 !== 0 || !/^[0-9a-f]+$/i.test(row))) {
        throw new Error('Invalid hexadecimal records in MEC 8.x.');
    }
    return rows.map(row => Buffer.from(row, 'hex'));
}

function padLegacyRow(row, padding) {
    const length = Math.ceil((row.length + padding.minimum) / 8) * 8;
    const padded = Buffer.alloc(length, padding.fill);
    row.copy(padded);
    if (padding.nul === 'start') padded[row.length] = 0;
    if (padding.nul === 'end') padded[length - 1] = 0;
    return padded;
}

function inferPadding(rows, decrypted) {
    for (const fill of [0x20, 0]) {
        for (const minimum of [0, 1, 2]) {
            const positions = minimum && fill !== 0 ? ['none', 'start', 'end'] : ['none'];
            for (const nul of positions) {
                const rule = { fill, minimum, nul };
                if (rows.every((row, index) => padLegacyRow(row, rule).equals(decrypted[index]))) return rule;
            }
        }
    }
    return undefined;
}

function candidatesInOrder(cached, candidates) {
    return cached ? [cached, ...candidates.filter(value => !value.equals(cached))] : candidates;
}

function readLegacy(header, keys, memo) {
    const ciphertext = legacyRows(header.body);
    for (const key of candidatesInOrder(memo[header.version], keys.line)) {
        if (!withoutPadding(blowfish(ciphertext.at(-1), key, true)).equals(Buffer.from('999'))) continue;
        const decrypted = ciphertext.map(row => blowfish(row, key, true));
        const records = decrypted.map(withoutPadding);
        if (!validRecords(records)) continue;

        memo[header.version] = key;
        const source = header.body.toString('latin1');
        const tail = /[\r\n]*$/.exec(source)[0];
        const profile = profileToken({
            version: header.version, key, headerEol: header.headerEol,
            rowEol: header.headerEol, tail, upper: !/[a-f]/.test(source),
            padding: inferPadding(records, decrypted),
        });
        return { version: header.version, records, profile };
    }
    throw new Error('None of the supplied format parameters could read this MEC 8.x.');
}

function xor(left, right) {
    const result = Buffer.alloc(left.length);
    for (let index = 0; index < left.length; index++) result[index] = left[index] ^ right[index];
    return result;
}

function splitPlaintext(plain) {
    const texts = plain.toString('latin1');
    const separators = texts.match(/\r\n|\n|\r/g) ?? [];
    const rows = texts.split(/\r\n|\n|\r/);
    const terminal = separators.length > 0 && rows.at(-1) === '';
    if (terminal) rows.pop();
    return { records: rows.map(row => Buffer.from(row, 'latin1')), separators, terminal };
}

function decipherAes(body, key, iv) {
    try {
        const cipher = createDecipheriv('aes-128-cbc', key, iv);
        const plaintext = Buffer.concat([cipher.update(body), cipher.final()]);
        const parsed = splitPlaintext(plaintext);
        if (validRecords(parsed.records)) return parsed;
    } catch {
        // Wrong parameters usually fail PKCS#7 validation.
    }
    return undefined;
}

function readModern(header, keys, memo) {
    const data = header.body;
    if (data.length < 32 || data.length % 16 !== 0) throw new Error('Invalid ciphertext length in MEC 9.2.');
    const result = (parsed, key, iv) => {
        memo.aes = { key, iv };
        const profile = profileToken({
            version: header.version, key, iv, headerEol: header.headerEol,
            rowEol: parsed.separators[0] ?? '\n', terminal: parsed.terminal,
            separators: parsed.separators,
        });
        return { version: header.version, records: parsed.records, profile };
    };
    if (memo.aes) {
        const { key, iv } = memo.aes;
        const parsed = decipherAes(data, key, iv);
        if (parsed) return result(parsed, key, iv);
    }
    if (keys.explicit.file.length === 1 && keys.explicit.iv.length === 1) {
        const key = keys.explicit.file[0];
        const iv = keys.explicit.iv[0];
        const parsed = decipherAes(data, key, iv);
        if (parsed) return result(parsed, key, iv);
    }

    const blocks = Buffer.concat([data.subarray(0, 16), data.subarray(-16)]);
    const penultimate = data.subarray(-32, -16);
    const ivs = candidatesInOrder(memo.aes?.iv, keys.iv);
    for (const key of candidatesInOrder(memo.aes?.key, keys.file)) {
        const cipher = createDecipheriv('aes-128-ecb', key, null).setAutoPadding(false);
        const plaintext = Buffer.concat([cipher.update(blocks), cipher.final()]);
        const tail = xor(plaintext.subarray(16), penultimate);
        const padding = tail.at(-1);
        if (padding < 1 || padding > 16 || !tail.subarray(-padding).every(b => b === padding)) continue;

        for (const iv of ivs) {
            const first = xor(plaintext.subarray(0, 16), iv).toString('latin1');
            if (!/^[ \t]*\d[\d .+\-eEA\t\r\n]*$/.test(first)) continue;
            const parsed = decipherAes(data, key, iv);
            if (parsed) return result(parsed, key, iv);
        }
    }
    throw new Error('None of the supplied format parameters could read this MEC 9.2.');
}

function readMec(buffer, keys, memo = {}) {
    const header = headerOf(buffer);
    const store = getKeys(keys);
    let state = memoStores.get(memo);
    if (state?.owner !== keys) {
        state = { owner: keys };
        memoStores.set(memo, state);
    }
    return header.version === '9.2' ? readModern(header, store, state) : readLegacy(header, store, state);
}

function assertTarget(version) {
    if (!WRITE_VERSIONS.has(version)) throw new Error('MEC output version must be 8.2 or 9.2.');
}

function encodingProfile(version, keys, referenceBuffer) {
    assertTarget(version);
    const store = getKeys(keys);
    if (referenceBuffer) {
        const { version: actual, profile, records } = readMec(referenceBuffer, keys);
        if (actual !== version) throw new Error(`The output reference must be MEC ${version}.`);
        if (!writeMec(records, version, profile).equals(referenceBuffer)) {
            throw new Error('The MEC output profile cannot reproduce the supplied reference.');
        }
        return profile;
    }
    if (version === '8.2' && store.explicit.line.length === 1) {
        return profileToken({
            version, key: store.explicit.line[0], headerEol: '\r\n', rowEol: '\r\n',
            tail: '\r\n\r\n', upper: true, padding: { fill: 0x20, minimum: 0, nul: 'none' },
        });
    }
    if (version === '9.2' && store.explicit.file.length === 1 && store.explicit.iv.length === 1) {
        return profileToken({
            version, key: store.explicit.file[0], iv: store.explicit.iv[0],
            headerEol: '\n', rowEol: '\n', terminal: true,
        });
    }
    throw new Error(`Supply a known-good MEC ${version} output reference or one explicit set of output keys.`);
}

function writeMec(records, version, profile) {
    assertTarget(version);
    const settings = profiles.get(profile);
    if (settings?.version !== version) throw new Error(`Expected a MEC ${version} output profile.`);
    if (!Array.isArray(records) || records.some(row => !Buffer.isBuffer(row) || row.includes(10) || row.includes(13))
        || !validRecords(records)) {
        throw new Error('Expected MEC records as Buffers ending with one 999 record.');
    }
    const header = `0 FILEMECLT ${version}${settings.headerEol}`;
    if (version === '8.2') {
        if (!settings.padding) throw new Error('Unable to determine the padding rule for the MEC 8.2 profile.');
        // The 9.2 body can include trailing separators in its text rows.
        // For 8.2 those bytes are indistinguishable from padding.
        const rows = records.map(withoutPadding).filter(row => row.length).map(row => {
            const hex = blowfish(padLegacyRow(row, settings.padding), settings.key, false).toString('hex');
            return settings.upper ? hex.toUpperCase() : hex;
        });
        return Buffer.from(header + rows.join(settings.rowEol) + settings.tail, 'ascii');
    }

    const plaintext = [];
    const separatorCount = records.length - (settings.terminal ? 0 : 1);
    const observed = settings.separators?.length === separatorCount ? settings.separators : null;
    for (const [index, row] of records.entries()) {
        plaintext.push(row);
        if (index < separatorCount) plaintext.push(Buffer.from(observed?.[index] ?? settings.rowEol, 'ascii'));
    }
    const cipher = createCipheriv('aes-128-cbc', settings.key, settings.iv);
    return Buffer.concat([Buffer.from(header, 'ascii'), cipher.update(Buffer.concat(plaintext)), cipher.final()]);
}

module.exports = { loadKeys, readMec, writeMec, encodingProfile };
