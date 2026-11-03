// Projected read for Codex. Never reads the real file content.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const [manifestArg, repoArg, relArg] = process.argv.slice(2);
const repo = path.resolve(repoArg);
const manifest = path.resolve(manifestArg);
const engine = require(path.join(repo, '.guard', 'v32_engine.js'));
const ctx = engine.context(repo, manifest);
const rel = engine.canonical(ctx, relArg);
const projected = engine.project(ctx, rel);
process.stdout.write(projected.text);
