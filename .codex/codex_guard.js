// Codex hook adapter for the v3.6/v3.2-compatible guard.
// Read-only convenience: list filenames, or translate PowerShell reads/searches
// into the guard's controlled cat/rg jobs. Never allows raw file content.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { raw += c; });
process.stdin.on('end', () => {
  let data = {};
  try { data = JSON.parse(raw || '{}'); } catch (_) { data = {}; }
  if (/^(PostToolUse|AfterTool)$/i.test(String(data.hook_event_name || ''))) process.exit(0);
  const tool = String(data.tool_name || '');
  const input = data.tool_input || {};
  const repo = path.resolve(data.cwd || process.argv[3] || process.cwd());
  const caseRoot = path.dirname(repo);
  const guard = path.join(repo, '.guard', 'v3_guard.js');
  let manifest = path.join(caseRoot, 'v3_manifest.json');
  if (!fs.existsSync(manifest)) manifest = path.join(repo, '.guard', 'v3_manifest.json');
  const allow = () => process.exit(0);
  const deny = (reason) => {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    }));
  };
  const delegate = (command) => {
    const payload = {
      ...data,
      tool_name: 'Bash',
      tool_input: { ...input, command },
    };
    const p = spawnSync('node', [guard, 'projection', 'codex', repo, manifest], {
      input: JSON.stringify(payload), encoding: 'utf8', timeout: 30000,
    });
    if (p.status !== 0) return deny('CODEX_GUARD_ERROR');
    if (p.stdout) process.stdout.write(p.stdout);
    else process.exit(0);
  };
  const stripOuter = (cmd) => {
    let s = String(cmd || '').trim();
    // Codex may invoke PowerShell/CMD wrappers; extract the inner -Command.
    const m = s.match(/^(?:"[^"]*pwsh\.exe"|"[^"]*powershell\.exe"|pwsh(?:\.exe)?|powershell(?:\.exe)?)\s+(?:-NoProfile\s+)?-Command\s+([\s\S]+)$/i);
    if (m) {
      s = m[1].trim();
      if (/^".*"$/.test(s)) s = s.slice(1, -1);
    }
    // Strip a harmless explicit cd to this repo.
    const cd = s.match(/^cd\s+(?:"([^"]+)"|'([^']+)'|(\S+))\s*&&\s*([\s\S]+)$/i);
    if (cd) {
      const target = path.resolve(repo, cd[1] || cd[2] || cd[3]);
      if (target.toLowerCase() === repo.toLowerCase()) s = cd[4].trim();
    }
    return s;
  };

  const hasCompound = (s) => {
    let quote = null;
    for (const ch of String(s || '')) {
      if (quote) { if (ch === quote) quote = null; continue; }
      if (ch === '"' || ch === "'") { quote = ch; continue; }
      if ('|;&><'.includes(ch)) return true;
    }
    return false;
  };
  const normalizeRg = (s) => {
    let c = String(s || '')
      .replace(/(^|\s)-F(?=\s|$)/g, ' ')
      .replace(/(^|\s)--color(?:=\S+)?(?=\s|$)/g, ' ')
      .replace(/(^|\s)--no-heading(?=\s|$)/g, ' ')
      .replace(/(^|\s)-S(?=\s|$)/g, ' ')
      .replace(/(^|\s)--line-number(?=\s|$)/g, ' -n ')
      .replace(/(^|\s)--ignore-case(?=\s|$)/g, ' -i ');
    const m = c.match(/^rg\s+((?:(?:-i|-n|-C\s+\d+|--context\s+\d+)\s+)*)(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+(.+))?$/);
    if (!m) return c;
    const flags = (m[1] || '').replace(/--context\s+(\d+)/g, '-C $1').trim();
    const pattern = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
    // The guard supports one search root. Collapse multiple explicit paths to '.'.
    return 'rg' + (flags ? ' ' + flags : '') + ' "' + String(pattern).replace(/"/g, '') + '" .';
  };

  const search = (pattern, target = '.') => {
    const b64 = Buffer.from(String(pattern || ''), 'utf8').toString('base64');
    const script = path.join(repo, '.codex', 'codex_search.js');
    const cmd = 'node "' + script + '" "' + manifest + '" "' + repo + '" "' + b64 + '" "' + String(target || '.').replace(/"/g, '') + '"';
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse', permissionDecision: 'allow',
        updatedInput: { ...input, command: cmd },
      },
    }));
  };
  const read = (target) => {
    const script = path.join(repo, '.codex', 'codex_read.js');
    const cmd = 'node "' + script + '" "' + manifest + '" "' + repo + '" "' + String(target || '').replace(/"/g, '') + '"';
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse', permissionDecision: 'allow',
        updatedInput: { ...input, command: cmd },
      },
    }));
  };
  const parseRg = (s) => {
    const rest = s.replace(/^rg\s+/i, '');
    const toks = rest.match(/"[^"]*"|'[^']*'|\S+/g) || [];
    const vals = [];
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (/^-C$/.test(t) || /^--context$/.test(t)) { i++; continue; }
      if (t.startsWith('-')) continue;
      vals.push(t.replace(/^["']|["']$/g, ''));
    }
    const pattern = vals.shift() || '';
    const target = vals.length === 1 ? vals[0] : '.';
    return { pattern, target };
  };

  if (tool === 'Bash' || tool === 'shell' || tool === 'command') {
    const command = stripOuter(input.command || input.cmd || '');
    if (!command) return deny('CODEX_EMPTY_COMMAND');
    if (hasCompound(command)) return deny('CODEX_COMPOUND_COMMAND_UNSUPPORTED');

    // Filename-only enumeration is public metadata; do not allow compound commands.
    if (/^(?:rg\s+--files|git\s+ls-files|git\s+diff\s+--cached\s+--name-only|git\s+show\s+--name-only(?:\s+HEAD)?|git\s+status\s+--short|Get-ChildItem(?:\s+[^|;&><]*)?|dir(?:\s+[^|;&><]*)?|ls(?:\s+[^|;&><]*)?)(?:\s+[^|;&><]*)?$/i.test(command)) {
      return allow();
    }
    if (/^pwd$/i.test(command)) return delegate('pwd');

    // PowerShell content reads/searches -> controlled cat/rg.
    let m = command.match(/^(?:Get-Content|gc|type|cat)\s+(?:-Raw\s+)?(?:-Path\s+)?(.+)$/i);
    if (m) {
      let p = m[1].trim().replace(/^["']|["']$/g, '');
      if (!p || p.startsWith('-')) return deny('CODEX_READ_ARGUMENTS_UNSUPPORTED');
      return read(p);
    }
    m = command.match(/^Select-String\s+(?:-Pattern\s+)?["']([^"']+)["'](?:\s+-Path\s+)?\s+(.+)$/i);
    if (m) {
      let p = m[2].trim().replace(/^["']|["']$/g, '').replace(/^@\(/, '').replace(/\)$/, '');
      if (!p || p.startsWith('-')) return deny('CODEX_SEARCH_ARGUMENTS_UNSUPPORTED');
      return search(m[1], p);
    }
    if (/^rg\b/i.test(command)) {
      const q = parseRg(command);
      return search(q.pattern, q.target);
    }
    return deny('CODEX_COMMAND_UNSUPPORTED');
  }

  if (['read', 'read_file', 'readfile'].includes(tool.toLowerCase())) {
    const payload = { ...data, tool_name: 'Read', tool_input: { ...input } };
    const p = spawnSync('node', [guard, 'projection', 'codex', repo, manifest], {
      input: JSON.stringify(payload), encoding: 'utf8', timeout: 30000,
    });
    if (p.status !== 0) return deny('CODEX_GUARD_ERROR');
    if (p.stdout) process.stdout.write(p.stdout);
    else process.exit(0);
  }

  if (['edit', 'edit_file', 'replace', 'apply_patch', 'write', 'write_file'].includes(tool.toLowerCase())) {
    return deny('CODEX_EDIT_NOT_SUPPORTED_USE_CCB');
  }
  if (/^(?:mcp__|webrun|web_search|web_fetch)/i.test(tool)) {
    return deny('CODEX_TOOL_UNSUPPORTED');
  }
  deny('CODEX_TOOL_UNSUPPORTED');
});
