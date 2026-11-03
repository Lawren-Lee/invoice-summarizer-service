// Projected-view search for the Codex adapter. Never reads the real repo.
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const [manifest, repoArg, patternB64, pathArg = '.'] = process.argv.slice(2);
const repo = path.resolve(repoArg);
const engine = require(path.join(repo, '.guard', 'v32_engine.js'));
const ctx = engine.context(repo, path.resolve(manifest));
const view = engine.view(ctx);
let pattern = Buffer.from(patternB64 || '', 'base64').toString('utf8');
let re;
try { re = new RegExp(pattern, 'i'); } catch (_) { re = null; }
const wanted = path.resolve(view.root, pathArg);
const inside = (root, p) => {
  const r = path.relative(root, p);
  return r === '' || (!r.startsWith('..' + path.sep) && r !== '..' && !path.isAbsolute(r));
};
let out = '';
let count = 0;
for (const rel of engine.files(ctx)) {
  const abs = path.join(view.root, rel);
  if (!inside(wanted, abs) && path.resolve(view.root, rel) !== wanted) continue;
  let text = '';
  try { text = fs.readFileSync(abs, 'utf8'); } catch (_) { continue; }
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const hit = re ? re.test(lines[i]) : lines[i].includes(pattern);
    if (!hit) continue;
    out += rel + ':' + (i + 1) + ':' + lines[i] + '\n';
    if (++count > 2000) break;
  }
  if (count > 2000) break;
}
process.stdout.write(out);
