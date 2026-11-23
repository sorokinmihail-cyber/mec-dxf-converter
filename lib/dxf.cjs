'use strict';

const { makeDxf: makeContourDxf } = require('./geometry.cjs');
const ZERO_LENGTH = 1e-9;
const NUMBER = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i;
const POINT_LAYER = 'MEC_POINTS';
const TEXT_LAYER = 'MEC_ANNOTATIONS';
const ATTRIBUTES = new Set([12, 13, 17, 19, 20, 24]);
const ENTITY_SECTION = '0\r\nSECTION\r\n2\r\nENTITIES\r\n';
const EMPTY_DXF = [0, 'SECTION', 2, 'HEADER', 9, '$ACADVER', 1, 'AC1015',
  9, '$INSUNITS', 70, 4, 0, 'ENDSEC', 0, 'SECTION', 2, 'ENTITIES',
  0, 'ENDSEC', 0, 'EOF', ''].join('\r\n');

function isDegenerateLine(fields) {
  const values = fields.slice(4, 8);
  if (values.length !== 4 || !values.every(field => NUMBER.test(field))) return false;
  const [x0, y0, x1, y1] = values.map(Number);
  return Math.hypot(x1 - x0, y1 - y0) <= ZERO_LENGTH;
}

function countEntities(dxf) {
  const counts = { LINE: 0, ARC: 0, CIRCLE: 0, POINT: 0, TEXT: 0 };
  const groups = dxf.split('\r\n');
  for (let i = 0; i + 1 < groups.length; i += 2) {
    const type = groups[i + 1];
    if (groups[i] === '0' && Object.hasOwn(counts, type)) counts[type]++;
  }
  return counts;
}

function asciiDxfText(text) {
  let decoded = text;
  // The MEC cipher reader maps bytes to Latin-1. Text in those bytes can be
  // stored as UTF-8 (newer) or Windows-1251 (legacy Russian labels).
  if (!/[^\x00-\xFF]/.test(text)) {
    const bytes = Buffer.from(text, 'latin1');
    try {
      decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      decoded = new TextDecoder('windows-1251').decode(bytes);
    }
  }
  return decoded.replace(/[^\x20-\x7E]|[%\\]/g, character =>
    '\\U+' + character.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'));
}

function numericValues(fields, count, index) {
  if (fields.length !== count ||
      !fields.every(field => NUMBER.test(field) && Number.isFinite(Number(field)))) {
    throw new Error('Invalid supplemental geometry in MEC line ' + (index + 1));
  }
  return fields.map(Number);
}

function pointGroups(fields, index) {
  const [x, y, z] = numericValues(fields.slice(4), 3, index);
  return [0, 'POINT', 100, 'AcDbEntity', 8, POINT_LAYER, 100, 'AcDbPoint', 10, x, 20, y, 30, z];
}

function labelRecord(line, index) {
  const spans = [...line.matchAll(/\S+/g)].slice(-18);
  const values = numericValues(spans.map(span => span[0]), 18, index);
  const prefix = line.slice(0, spans[0].index).trim();
  const match = prefix.match(/^(?:6\s+\d+\s+\d+\s+\d+|25)\s+"([^"]*)"\s+"(.*)"$/);
  if (!match) throw new Error('Invalid quoted label in MEC line ' + (index + 1));
  const [x, y, bx, by] = values;
  const height = values[16];
  const rotation = (Math.atan2(by - y, bx - x) * 180 / Math.PI + 360) % 360;
  return { x, y, height, rotation, text: asciiDxfText(match[2]), font: asciiDxfText(match[1]) };
}

function textGroups({ x, y, height, rotation, text }) {
  return [0, 'TEXT', 100, 'AcDbEntity', 8, TEXT_LAYER, 100, 'AcDbText', 10, x, 20, y,
    30, 0, 40, height, 1, text, 50, rotation, 7, 'STANDARD', 100, 'AcDbText', 73, 0];
}

function layerGroups(layers) {
  if (!layers.size) return [];
  const groups = [0, 'SECTION', 2, 'TABLES', 0, 'TABLE', 2, 'LAYER',
    100, 'AcDbSymbolTable', 70, layers.size + 1];
  for (const layer of ['0', ...layers]) {
    groups.push(0, 'LAYER', 100, 'AcDbSymbolTableRecord', 100, 'AcDbLayerTableRecord',
      2, layer, 70, 0, 62, 7, 6, 'CONTINUOUS');
  }
  groups.push(0, 'ENDTAB', 0, 'ENDSEC');
  return groups;
}

function addSupplementaryRecords(dxf, diagnostics, extraGroups, layers) {
  const comments = diagnostics.flatMap(text => [999, text]);
  const prefixGroups = layerGroups(layers).concat(comments);
  const prefix = prefixGroups.length ? prefixGroups.join('\r\n') + '\r\n' : '';
  const extras = extraGroups.length ? extraGroups.join('\r\n') + '\r\n' : '';
  return dxf.replace(ENTITY_SECTION, () => prefix + ENTITY_SECTION + extras);
}

function makeDxf(records, { version } = {}) {
  if (!Array.isArray(records)) throw new TypeError('MEC records must be a Buffer array');
  const lines = Array.from(records, record => {
    if (!Buffer.isBuffer(record)) throw new TypeError('MEC records must be a Buffer array');
    return record.toString('latin1');
  });

  const diagnostics = [];
  const extraGroups = [];
  const layers = new Set();
  const attributes = new Map();
  let role = 0;
  let leadIns = 0;
  let visibleLabels = 0;
  let ended = false;
  for (const [index, line] of lines.entries()) {
    if (ended) break;
    const fields = line.trim().split(/\s+/);
    if (!/^\d+$/.test(fields[0])) continue;
    const code = Number(fields[0]);
    if (code === 21) {
      role = Number(fields[1]);
    } else if ((code >= 61 && code <= 63) || (code >= 71 && code <= 73)) {
      role = 0;
    } else if (code >= 1 && code <= 3) {
      if (role === 1) {
        leadIns++;
      } else if (code === 1 && isDegenerateLine(fields)) {
        diagnostics.push('MEC line ' + (index + 1) + ': zero-length line omitted');
        // The discarded element still consumed the preceding machining role.
        lines[index] = '21 0';
      }
      role = 0;
    } else if (code === 5) {
      if (role === 1) {
        leadIns++;
      } else {
        extraGroups.push(...pointGroups(fields, index));
        layers.add(POINT_LAYER);
      }
      role = 0;
      lines[index] = '21 0';
    } else if (code === 6 || code === 25) {
      const label = labelRecord(line, index);
      const reference = /^&.*\.bmp(?:\s|$)/i.test(label.text);
      if (code === 25 || reference || label.height <= 0 || !label.text) {
        const reason = code === 25 ? 'stroke label metadata' :
          reference ? 'bitmap reference (image absent)' : 'nonprinting label';
        diagnostics.push('MEC line ' + (index + 1) + ': ' + reason + ' at ' +
          label.x + ',' + label.y + ' [' + label.font + '] ' + label.text);
      } else if (role === 1) {
        leadIns++;
      } else {
        extraGroups.push(...textGroups(label));
        layers.add(TEXT_LAYER);
        visibleLabels++;
      }
      if (code === 6) role = 0;
      lines[index] = code === 6 ? '21 0' : '';
    } else if (ATTRIBUTES.has(code)) {
      attributes.set(code, (attributes.get(code) ?? 0) + 1);
      lines[index] = '';
    } else if (code === 999) {
      ended = true;
    }
  }
  if (leadIns) diagnostics.push('Excluded machining lead-in elements: ' + leadIns);
  if (visibleLabels) diagnostics.push('MEC annotations exported with standard DXF font: ' + visibleLabels);
  if (attributes.size) {
    const summary = Array.from(attributes, ([code, count]) => code + ' (' + count + ')');
    diagnostics.push('Lantek-specific attributes not applied to DXF: ' + summary.join(', '));
  }

  let dxf;
  try {
    dxf = makeContourDxf(lines.join('\n'));
  } catch (error) {
    if (extraGroups.length && error.message === 'MEC contains no supported drawing geometry') {
      dxf = EMPTY_DXF;
    } else {
      error.diagnostics = diagnostics;
      error.version = version;
      throw error;
    }
  }
  dxf = addSupplementaryRecords(dxf, diagnostics, extraGroups, layers);
  return { dxf, diagnostics, counts: countEntities(dxf) };
}

module.exports = { makeDxf };
