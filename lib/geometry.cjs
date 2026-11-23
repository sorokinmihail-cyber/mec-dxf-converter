'use strict';

const TOLERANCE = 0.02;
const EPSILON = 1e-9;
const RADIANS = Math.PI / 180;
const TYPES = ['LINE', 'ARC', 'CIRCLE'];
const IDENTITY = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];

function normalize(angle) {
  return ((angle % 360) + 360) % 360;
}

function number(value, context) {
  if (!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value) ||
      !Number.isFinite(Number(value))) {
    throw new Error('Invalid number in ' + context);
  }
  return Number(value);
}

function pointGap(a, b) {
  return Math.hypot(a[0] - b[0], a[1] - b[1]);
}

function arcPoint(center, radius, angle) {
  const radians = angle * RADIANS;
  return [center[0] + radius * Math.cos(radians), center[1] + radius * Math.sin(radians)];
}

function lineEntity(start, end, context) {
  if (pointGap(start, end) <= EPSILON) throw new Error('Zero-length line in ' + context);
  return { type: 'LINE', start, end };
}

function circleEntity(center, radius, context) {
  if (radius <= 0) throw new Error('Nonpositive radius in ' + context);
  return { type: 'CIRCLE', center, radius };
}

function mecEntity(code, values, context) {
  if (code === 1) return lineEntity(values.slice(0, 2), values.slice(2), context);
  const [x, y, radius, angle, sweep] = values;
  const center = [x, y];
  const circle = circleEntity(center, radius, context);
  if (code === 3 || Math.abs(Math.abs(sweep) - 360) <= EPSILON) return circle;
  if (Math.abs(sweep) <= EPSILON || Math.abs(sweep) > 360) {
    throw new Error('Invalid arc sweep in ' + context);
  }
  const startError = pointGap(arcPoint(center, radius, angle), values.slice(5, 7));
  const endError = pointGap(arcPoint(center, radius, angle + sweep), values.slice(7, 9));
  if (Math.max(startError, endError) > TOLERANCE + EPSILON) {
    throw new Error('Arc endpoints disagree with center, radius or angles in ' + context);
  }
  return {
    ...circle,
    type: 'ARC',
    startAngle: normalize(sweep < 0 ? angle + sweep : angle),
    sweep: Math.abs(sweep),
  };
}

function readMecEntities(plain) {
  const input = Buffer.isBuffer(plain) ? plain.toString('utf8') : plain;
  if (typeof input !== 'string') throw new TypeError('Decoded MEC must be a string or Buffer');
  const entities = [];
  let role = 0;
  let ended = false;

  // Record semantics are documented in NestPro's MIT-licensed app/src/formats/mec.rs.
  const lines = input.replace(/\0+$/, '').split(/\r\n|\n|\r/);
  for (const [index, line] of lines.entries()) {
    const context = 'MEC line ' + (index + 1);
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (ended) throw new Error('Unexpected record after MEC terminator in ' + context);
    const tokens = trimmed.split(/\s+/);
    if (!/^\d+$/.test(tokens[0])) throw new Error('Invalid record code in ' + context);
    const code = Number(tokens[0]);

    if (code === 999) {
      if (tokens.length !== 1) throw new Error('Malformed MEC terminator in ' + context);
      ended = true;
    } else if (code === 21) {
      role = number(tokens[1], context);
      if (!Number.isInteger(role)) throw new Error('Invalid element role in ' + context);
    } else if ((code >= 61 && code <= 63) || (code >= 71 && code <= 73)) {
      role = 0;
    } else if (code === 92) {
      const matrix = IDENTITY.map((_, i) => number(tokens[i + 1], context));
      if (matrix.some((value, i) => Math.abs(value - IDENTITY[i]) > EPSILON)) {
        throw new Error('Nonidentity placement matrix in ' + context);
      }
    } else if (code >= 1 && code <= 3) {
      const values = Array.from({ length: [4, 9, 3][code - 1] }, (_, i) =>
        number(tokens[i + 4], context));
      if (role !== 1) entities.push(mecEntity(code, values, context));
      role = 0;
    } else if (![0, 16, 31, 32, 33, 81, 90, 91].includes(code) && (code < 38 || code > 60)) {
      throw new Error('Unsupported MEC record ' + code + ' in ' + context);
    }
  }
  if (!ended) throw new Error('MEC terminator 999 is missing');
  if (!entities.length) throw new Error('MEC contains no supported drawing geometry');
  return entities;
}

function makeDxf(plain) {
  const entities = readMecEntities(plain);
  const pairs = [0, 'SECTION', 2, 'HEADER', 9, '$ACADVER', 1, 'AC1015',
    9, '$INSUNITS', 70, 4, 0, 'ENDSEC', 0, 'SECTION', 2, 'ENTITIES'];
  for (const entity of entities) {
    pairs.push(0, entity.type, 100, 'AcDbEntity', 8, '0');
    if (entity.type === 'LINE') {
      pairs.push(100, 'AcDbLine', 10, entity.start[0], 20, entity.start[1], 30, 0,
        11, entity.end[0], 21, entity.end[1], 31, 0);
    } else {
      pairs.push(100, 'AcDbCircle', 10, entity.center[0], 20, entity.center[1], 30, 0,
        40, entity.radius);
      if (entity.type === 'ARC') {
        pairs.push(100, 'AcDbArc', 50, entity.startAngle,
          51, normalize(entity.startAngle + entity.sweep));
      }
    }
  }
  pairs.push(0, 'ENDSEC', 0, 'EOF', '');
  return pairs.join('\r\n');
}

function dxfEntity(type, fields, index) {
  const context = 'DXF ' + type + ' #' + (index + 1);
  const get = (code, fallback) => number(fields.get(code) ?? fallback, context);
  if (get(30, '0') !== 0 || get(31, '0') !== 0 || get(210, '0') !== 0 ||
      get(220, '0') !== 0 || get(230, '1') !== 1) {
    throw new Error('Nonplanar or transformed geometry in ' + context);
  }
  const center = [get(10), get(20)];
  if (type === 'LINE') return lineEntity(center, [get(11), get(21)], context);
  const circle = circleEntity(center, get(40), context);
  if (type === 'CIRCLE') return circle;
  const start = get(50);
  const sweep = normalize(get(51) - start);
  if (sweep <= EPSILON) throw new Error('Zero sweep in ' + context);
  return { ...circle, type: 'ARC', startAngle: normalize(start), sweep };
}

function readDxfEntities(dxf) {
  if (typeof dxf !== 'string') throw new TypeError('DXF must be a string');
  const lines = dxf.trim().split(/\r\n|\n|\r/);
  if (lines.length % 2 !== 0) throw new Error('Truncated group code/value pair');
  let foundSection = false;
  let current;
  const entities = [];
  for (let i = 0; i < lines.length; i += 2) {
    const code = lines[i].trim();
    const value = lines[i + 1].trim();
    if (!foundSection) {
      foundSection = code === '2' && value === 'ENTITIES' &&
        lines[i - 2]?.trim() === '0' && lines[i - 1]?.trim() === 'SECTION';
      continue;
    }
    if (code === '0') {
      if (current) entities.push(dxfEntity(current.type, current.fields, entities.length));
      if (value === 'ENDSEC') {
        if (!entities.length) throw new Error('DXF has no comparable geometry');
        return entities;
      }
      if (!TYPES.includes(value)) throw new Error('Unsupported DXF entity ' + value);
      current = { type: value, fields: new Map() };
    } else if (current) {
      current.fields.set(Number(code), value);
    }
  }
  throw new Error(foundSection ? 'DXF ENTITIES section is unterminated' :
    'DXF ENTITIES section is missing');
}

function counts(entities) {
  return Object.fromEntries(TYPES.map(type => [type, entities.filter(item => item.type === type).length]));
}

function meanAnchor(entities) {
  const mean = [0, 0];
  for (const entity of entities) {
    const anchor = entity.center ?? [
      (entity.start[0] + entity.end[0]) / 2,
      (entity.start[1] + entity.end[1]) / 2,
    ];
    mean[0] += anchor[0] / entities.length;
    mean[1] += anchor[1] / entities.length;
  }
  return mean;
}

function subtract(a, b) {
  return [a[0] - b[0], a[1] - b[1]];
}

function angleGap(a, b) {
  return Math.abs(normalize(a - b + 180) - 180);
}

function pairing(actual, reference, translation) {
  if (actual.type !== reference.type) return;
  const gap = deltas => Math.max(...deltas.map(delta => pointGap(delta, translation)));
  let deltas;
  if (actual.type === 'LINE') {
    const straight = [subtract(actual.start, reference.start), subtract(actual.end, reference.end)];
    const reversed = [subtract(actual.end, reference.start), subtract(actual.start, reference.end)];
    deltas = gap(straight) <= gap(reversed) ? straight : reversed;
  } else {
    if (Math.abs(actual.radius - reference.radius) > TOLERANCE + EPSILON) return;
    if (actual.type === 'ARC') {
      const radius = Math.max(actual.radius, reference.radius);
      const startGap = angleGap(actual.startAngle, reference.startAngle);
      const endGap = angleGap(actual.startAngle + actual.sweep, reference.startAngle + reference.sweep);
      const sweepGap = Math.abs(actual.sweep - reference.sweep);
      if (Math.max(startGap, endGap, sweepGap) * radius * RADIANS > TOLERANCE + EPSILON) return;
    }
    deltas = [subtract(actual.center, reference.center)];
  }
  const score = gap(deltas);
  if (score <= 2 * TOLERANCE + EPSILON) return { deltas, score };
}

function matchEntities(actual, reference, translation) {
  const candidates = reference.map(item => actual
    .map((object, index) => ({ index, pair: pairing(object, item, translation) }))
    .filter(candidate => candidate.pair)
    .sort((a, b) => a.pair.score - b.pair.score));
  const assignments = Array(actual.length).fill(null);
  function assign(referenceIndex, visited) {
    for (const candidate of candidates[referenceIndex]) {
      if (visited.has(candidate.index)) continue;
      visited.add(candidate.index);
      const previous = assignments[candidate.index];
      if (!previous || assign(previous.referenceIndex, visited)) {
        assignments[candidate.index] = { referenceIndex, pair: candidate.pair };
        return true;
      }
    }
    return false;
  }
  const unmatched = [];
  for (const [index, entity] of reference.entries()) {
    if (!assign(index, new Set())) unmatched.push(entity.type + ' #' + (index + 1));
  }
  return { unmatched, deltas: assignments.filter(Boolean).flatMap(item => item.pair.deltas) };
}

function maxPointGap(deltas, translation) {
  let gap = 0;
  for (const delta of deltas) gap = Math.max(gap, pointGap(delta, translation));
  return gap;
}

function fitTranslation(deltas, initial) {
  const lower = [Infinity, Infinity];
  const upper = [-Infinity, -Infinity];
  for (const delta of deltas) {
    for (const axis of [0, 1]) {
      lower[axis] = Math.min(lower[axis], delta[axis]);
      upper[axis] = Math.max(upper[axis], delta[axis]);
    }
  }
  const midpoint = lower.map((value, axis) => (value + upper[axis]) / 2);
  const radius = TOLERANCE + EPSILON;
  const error = maxPointGap(deltas, midpoint);
  if (error <= radius || upper.some((value, axis) => value - lower[axis] > 2 * radius)) {
    return midpoint;
  }
  if (maxPointGap(deltas, initial) <= radius) return initial;

  // A valid translation lies in every point's tolerance disk. If their
  // common region exists, its boundary has an intersection of two circles.
  const unique = [...new Map(deltas.map(delta => [delta.join(','), delta])).values()];
  for (const [i, a] of unique.entries()) {
    for (const b of unique.slice(i + 1)) {
      const length = pointGap(a, b);
      if (length > 2 * radius) return midpoint;
      const offset = Math.sqrt(Math.max(0, radius ** 2 - (length / 2) ** 2)) / length;
      const mid = [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2];
      for (const sign of [-1, 1]) {
        const candidate = [mid[0] - sign * offset * (b[1] - a[1]),
          mid[1] + sign * offset * (b[0] - a[0])];
        if (maxPointGap(deltas, candidate) <= radius) return candidate;
      }
    }
  }
  return midpoint;
}

function compareDxfString(actual, reference) {
  let actualEntities;
  let referenceEntities;
  let stage = 'Produced DXF';
  try {
    actualEntities = readDxfEntities(actual);
    stage = 'Reference DXF';
    referenceEntities = readDxfEntities(reference);
  } catch (error) {
    return { match: false, diagnostics: [stage + ': ' + error.message], matchedCount: 0 };
  }
  const actualCounts = counts(actualEntities);
  const referenceCounts = counts(referenceEntities);
  const result = { match: false, actualCounts, referenceCounts, matchedCount: 0, diagnostics: [] };
  for (const type of TYPES) {
    if (actualCounts[type] !== referenceCounts[type]) {
      result.diagnostics.push(type + ' count: ' + actualCounts[type] + ', expected ' + referenceCounts[type]);
    }
  }
  if (result.diagnostics.length) return result;

  const translation = subtract(meanAnchor(actualEntities), meanAnchor(referenceEntities));
  const matched = matchEntities(actualEntities, referenceEntities, translation);
  result.matchedCount = referenceEntities.length - matched.unmatched.length;
  if (matched.unmatched.length) {
    result.diagnostics.push('No matching geometry for: ' + matched.unmatched.slice(0, 10).join(', '));
    return result;
  }

  result.translation = fitTranslation(matched.deltas, translation);
  const maxGap = maxPointGap(matched.deltas, result.translation);
  result.maxPointErrorMm = maxGap;
  if (maxGap > TOLERANCE + EPSILON) {
    result.diagnostics.push('Largest displacement after translation: ' + maxGap.toFixed(4) + ' mm');
    return result;
  }
  result.match = true;
  return result;
}

module.exports = { makeDxf, compareDxfString };
