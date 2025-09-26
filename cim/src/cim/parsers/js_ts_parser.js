#!/usr/bin/env node
const fs = require('fs');

const IMPORT_RE = /import\s+(?:[^'";]+?)\s+from\s+['\"]([^'\"]+)['\"]/g;
const IMPORT_SIDE_EFFECT_RE = /import\s+['\"]([^'\"]+)['\"]/g;
const REQUIRE_RE = /require\((['\"])([^'\"]+)\1\)/g;
const EXPORT_DECL_RE = /export\s+(default\s+)?(class|function|const|let|var)\s+([A-Za-z0-9_]+)/g;
const EXPORT_LIST_RE = /export\s*{([^}]+)}/g;
const COMPONENT_RE = /<([A-Z][A-Za-z0-9_]*)\b/g;
const PROCESS_ENV_RE = /process\.env\.([A-Z0-9_]+)/g;
const I18N_RE = /i18n\.(?:t|get)\((['\"])([^'\"]+)\1/g;

function uniq(items) {
  return Array.from(new Set(items));
}

function parseFile(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  const imports = [];
  const specs = [];

  let match;
  while ((match = IMPORT_RE.exec(code)) !== null) {
    imports.push({ source: match[1], kind: 'import' });
  }
  while ((match = IMPORT_SIDE_EFFECT_RE.exec(code)) !== null) {
    imports.push({ source: match[1], kind: 'import' });
  }
  while ((match = REQUIRE_RE.exec(code)) !== null) {
    imports.push({ source: match[2], kind: 'require' });
  }

  const exports = [];
  while ((match = EXPORT_DECL_RE.exec(code)) !== null) {
    exports.push({ name: match[3], kind: match[2], isDefault: Boolean(match[1]) });
  }
  while ((match = EXPORT_LIST_RE.exec(code)) !== null) {
    const names = match[1]
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);
    names.forEach((name) => exports.push({ name, kind: 'named', isDefault: false }));
  }

  const components = [];
  while ((match = COMPONENT_RE.exec(code)) !== null) {
    components.push(match[1]);
  }

  const resources = [];
  while ((match = PROCESS_ENV_RE.exec(code)) !== null) {
    resources.push({ kind: 'env', value: match[1] });
  }
  while ((match = I18N_RE.exec(code)) !== null) {
    resources.push({ kind: 'i18n', value: match[2] });
  }

  return {
    imports,
    exports: uniq(exports.map((item) => JSON.stringify(item))).map((item) => JSON.parse(item)),
    components: uniq(components),
    resources: uniq(resources.map((item) => JSON.stringify(item))).map((item) => JSON.parse(item)),
  };
}

if (require.main === module) {
  const file = process.argv[2];
  if (!file) {
    console.error('Usage: node js_ts_parser.js <file>');
    process.exit(1);
  }
  try {
    const result = parseFile(file);
    process.stdout.write(JSON.stringify(result));
  } catch (err) {
    process.stderr.write(String(err));
    process.exit(2);
  }
}

module.exports = { parseFile };
