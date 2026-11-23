'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { loadKeys, readMec, writeMec, encodingProfile } = require('../lib/mec.cjs');
const { makeDxf } = require('../lib/dxf.cjs');
const { main } = require('../convert.cjs');

// These deliberately made-up values have no connection to Lantek installations.
const demoKeys = {
  'line-key': Buffer.from('fake-bfish-k-012'),
  'file-key': Buffer.from('fake-aes-key-012'),
  'file-iv': Buffer.from('fake-iv-demo-012'),
};

const records = [
  '90 0 0 100 60',
  '91 0 4 1 2 0 0 0 0 0',
  '92 1 0 0 0 0 1 0 0 0 0 1 0 0 0 0 1',
  '1 0 0 0 0 0 80 0',
  '2 0 0 0 80 20 20 270 90 80 0 100 20',
  '1 1 0 0 100 20 100 60',
  '1 2 0 0 100 60 0 60',
  '1 3 0 0 0 60 0 0',
  '3 0 0 0 30 25 7',
  '3 1 0 0 65 37 5',
].map(value => Buffer.from(value));
records.push(
  Buffer.concat([
    Buffer.from('31 2 1145 1 0 0 0 "'),
    Buffer.from('c4e5f2e0ebfc', 'hex'), // "Part" in Windows-1251.
    Buffer.from('"'),
  ]),
  Buffer.from('999'),
);

function syntheticMec82() {
  const encryptedLines = records.map(record => {
    const size = Math.ceil(record.length / 8) * 8;
    const padded = Buffer.alloc(size, 0x20);
    record.copy(padded);
    const cipher = crypto.createCipheriv('bf-cbc', demoKeys['line-key'], Buffer.alloc(8));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(padded), cipher.final()]).toString('hex').toUpperCase();
  });
  return Buffer.from(['0 FILEMECLT 8.2', ...encryptedLines, '', ''].join('\r\n'));
}

function syntheticMec92() {
  const payload = Buffer.concat(records.flatMap(record => [record, Buffer.from('\n')]));
  const cipher = crypto.createCipheriv('aes-128-cbc', demoKeys['file-key'], demoKeys['file-iv']);
  return Buffer.concat([Buffer.from('0 FILEMECLT 9.2\n'), cipher.update(payload), cipher.final()]);
}

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mec-dxf-synthetic-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeKeyFile(directory, name = 'example.keys', values = demoKeys) {
  const keyFile = path.join(directory, name);
  const lines = Object.entries(values).map(([name, value]) => name + ' = ' + value.toString('hex'));
  fs.writeFileSync(keyFile, lines.join('\n') + '\n');
  return keyFile;
}

function readDxfEntities(dxf) {
  const lines = dxf.trim().split(/\r?\n/).map(line => line.trim());
  const start = lines.findIndex((value, i) => value === 'ENTITIES' &&
    lines[i - 1] === '2' && lines[i - 2] === 'SECTION');
  assert(start >= 0, 'DXF must contain an ENTITIES section');
  const entities = [];
  let entity;
  for (let i = start + 1; i < lines.length; i += 2) {
    const [code, value] = [Number(lines[i]), lines[i + 1]];
    if (code === 0) {
      if (value === 'ENDSEC') return entities;
      entity = { type: value, fields: new Map() };
      entities.push(entity);
    } else if (entity) {
      entity.fields.set(code, value);
    }
  }
  assert.fail('DXF ENTITIES section has no terminator');
}

function verifyNativeGeometry(dxf) {
  const entities = readDxfEntities(dxf);
  const type = name => entities.filter(entity => entity.type === name);
  const values = (entity, codes) => codes.map(code => Number(entity.fields.get(code)));
  assert.equal(entities.length, 7);
  assert.deepEqual(type('LINE').map(line => values(line, [10, 20, 11, 21])), [
    [0, 0, 80, 0], [100, 20, 100, 60], [100, 60, 0, 60], [0, 60, 0, 0],
  ]);
  const arcs = type('ARC');
  assert.equal(arcs.length, 1);
  const [x, y, radius, start, end] = values(arcs[0], [10, 20, 40, 50, 51]);
  assert.deepEqual([x, y, radius, start], [80, 20, 20, 270]);
  assert.equal(end % 360, 0);
  assert.deepEqual(type('CIRCLE').map(circle => values(circle, [10, 20, 40])), [
    [30, 25, 7], [65, 37, 5],
  ]);
}

function assertCliSuccess(...args) {
  assert.equal(main(args) ?? 0, 0);
}

test('both independently encrypted MEC versions preserve raw records through re-encoding', t => {
  const directory = temporaryDirectory(t);
  const keys = loadKeys({ keyFile: writeKeyFile(directory) });
  const oldFile = syntheticMec82();
  const newFile = syntheticMec92();
  const oldRead = readMec(oldFile, keys);
  const newRead = readMec(newFile, keys);
  assert.equal(oldRead.version, '8.2');
  assert.equal(newRead.version, '9.2');
  assert.deepEqual(oldRead.records, records);
  assert.deepEqual(newRead.records, records);
  const target82 = encodingProfile('8.2', keys, oldFile);
  const target92 = encodingProfile('9.2', keys, newFile);
  assert.deepEqual(writeMec(newRead.records, '8.2', target82), oldFile);
  assert.deepEqual(writeMec(oldRead.records, '9.2', target92), newFile);
  for (const version of ['8.2', '9.2']) {
    const standalone = writeMec(records, version, encodingProfile(version, keys));
    assert.deepEqual(readMec(standalone, keys).records, records);
  }
  verifyNativeGeometry(makeDxf(oldRead.records, { version: oldRead.version }).dxf);
  verifyNativeGeometry(makeDxf(newRead.records, { version: newRead.version }).dxf);
});

test('wrong keys and damaged envelopes are rejected', t => {
  const directory = temporaryDirectory(t);
  const keys = loadKeys({ keyFile: writeKeyFile(directory) });
  const wrong = Object.fromEntries(Object.keys(demoKeys).map(name => [name, Buffer.alloc(16, 0x55)]));
  const wrongKeys = loadKeys({ keyFile: writeKeyFile(directory, 'wrong.keys', wrong) });
  const oldFile = syntheticMec82();
  const newFile = syntheticMec92();
  assert.throws(() => readMec(oldFile, wrongKeys));
  assert.throws(() => readMec(newFile, wrongKeys));
  const damagedHex = Buffer.from(oldFile);
  damagedHex[oldFile.indexOf(0x0a) + 1] = 0x47;
  assert.throws(() => readMec(damagedHex, keys));
  assert.throws(() => readMec(newFile.subarray(0, -1), keys));
});

test('CLI uses only a key file, converts between MEC versions and keeps the DXF tree', t => {
  const directory = temporaryDirectory(t);
  const keyFile = writeKeyFile(directory);
  const oldFixture = path.join(directory, 'reference-82.mec');
  const newFixture = path.join(directory, 'reference-92.mec');
  fs.writeFileSync(oldFixture, syntheticMec82());
  fs.writeFileSync(newFixture, syntheticMec92());

  const oldOutput = path.join(directory, 'converted-82.mec');
  const newOutput = path.join(directory, 'converted-92.mec');
  assertCliSuccess('--to', '8.2', '--out', oldOutput, '--key-file', keyFile,
    '--target-reference', oldFixture, newFixture);
  assertCliSuccess('--to', '9.2', '--out', newOutput, '--key-file', keyFile,
    '--target-reference', newFixture, oldOutput);
  assert.deepEqual(fs.readFileSync(oldOutput), syntheticMec82());
  assert.deepEqual(fs.readFileSync(newOutput), syntheticMec92());

  const inputTree = path.join(directory, 'parts');
  const outputTree = path.join(directory, 'dxf');
  fs.mkdirSync(path.join(inputTree, 'first', 'nested'), { recursive: true });
  fs.mkdirSync(path.join(inputTree, 'second'), { recursive: true });
  fs.mkdirSync(path.join(inputTree, 'empty', 'deeper'), { recursive: true });
  fs.copyFileSync(oldOutput, path.join(inputTree, 'first', 'nested', 'part.mec'));
  fs.copyFileSync(newOutput, path.join(inputTree, 'second', 'part.mec'));
  assertCliSuccess('--to', 'dxf', '--out', outputTree, '--key-file', keyFile, inputTree);
  const first = path.join(outputTree, 'first', 'nested', 'part.dxf');
  const second = path.join(outputTree, 'second', 'part.dxf');
  verifyNativeGeometry(fs.readFileSync(first, 'utf8'));
  verifyNativeGeometry(fs.readFileSync(second, 'utf8'));
  assert(fs.statSync(path.join(outputTree, 'empty', 'deeper')).isDirectory());

  const sentinel = 'Existing user content\n';
  fs.writeFileSync(first, sentinel);
  assert.throws(() => main(['--to', 'dxf', '--out', first, '--key-file', keyFile, oldFixture]),
    /Output already exists/);
  assert.equal(fs.readFileSync(first, 'utf8'), sentinel);
  assert.deepEqual(fs.readFileSync(oldFixture), syntheticMec82());
});
