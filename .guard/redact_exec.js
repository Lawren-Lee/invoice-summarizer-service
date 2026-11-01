// Dynamic output taint filter for shell/tool execution.
// Runs a command, captures stdout/stderr, replaces the protected value and a
// few common encodings of it, and forwards the filtered bytes. The real value
// is read from the protected file at run time and is never printed.
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : def;
}

const secretFile = arg("--secret-file", "");
const cwd = arg("--cwd", process.cwd());
const commandFile = arg("--command-file", "");

let secret = "";
try {
  const t = fs.readFileSync(secretFile, "utf8");
  const m = t.match(/(?:LAB_TOKEN|OPENAI_API_KEY|SERVICE_API_KEY)\s*=\s*["']?([^"'\s]+)["']?/);
  secret = m ? m[1] : t.trim();
} catch (_) {
  secret = "";
}

let cmd = "";
try {
  cmd = fs.readFileSync(commandFile, "utf8");
} catch (_) {
  cmd = "";
}
try {
  fs.unlinkSync(commandFile);
} catch (_) {}

function variants() {
  if (!secret) return [];
  const out = new Set();
  out.add(secret);
  try {
    const raw = Buffer.from(secret, "utf8");
    out.add(raw.toString("base64"));
    out.add(raw.toString("hex"));
    out.add(raw.toString("hex").toUpperCase());
    out.add(encodeURIComponent(secret));

    // Common reversible transforms. These are not a complete IFC; they close
    // the cheap "reverse / swap / rot13 then print" paths.
    const reversed = secret.split("").reverse().join("");
    out.add(reversed);
    out.add(Buffer.from(raw).reverse().toString("utf8"));
    out.add(Buffer.from(raw).reverse().toString("base64"));

    const swab = Buffer.from(raw);
    for (let i = 0; i + 1 < swab.length; i += 2) {
      const t = swab[i]; swab[i] = swab[i + 1]; swab[i + 1] = t;
    }
    out.add(swab.toString("utf8"));
    out.add(swab.toString("base64"));

    const shift = (k) => secret.replace(/[a-zA-Z]/g, (c) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + k + 26) % 26) + base);
    });
    out.add(shift(13));
    for (let k = 1; k < 26; k++) out.add(shift(k));
    const atbash = secret.replace(/[a-zA-Z]/g, (c) => {
      const code = c.charCodeAt(0);
      return String.fromCharCode(code <= 90 ? 155 - code : 219 - code);
    });
    out.add(atbash);

    out.add(secret.toLowerCase());
    out.add(secret.toUpperCase());
  } catch (_) {}
  return Array.from(out).filter((x) => x && x.length > 0);
}

const VS = variants();

function redactBuffer(buf) {
  if (!secret || !buf || buf.length === 0) return buf;
  let out = buf;
  for (const v of VS) {
    const needle = Buffer.from(v, "utf8");
    if (!needle.length) continue;
    let idx = out.indexOf(needle);
    while (idx !== -1) {
      out = Buffer.concat([
        out.subarray(0, idx),
        Buffer.from("[REDACTED]", "utf8"),
        out.subarray(idx + needle.length),
      ]);
      idx = out.indexOf(needle, idx + "[REDACTED]".length);
    }
  }
  // Line-level backstop: remove whitespace and re-check, so "t o k _ ..."
  // and Caesar/atbash-shifted lines are caught even when byte replacement
  // missed the exact transformed span.
  try {
    const text = out.toString("utf8");
    const lines = text.split(/\r?\n/);
    let changed = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const compact = line.replace(/[^A-Za-z0-9_]+/g, "");
      if (VS.some((v) => v && (line.includes(v) || compact.includes(v)))) {
        lines[i] = "[REDACTED]";
        changed = true;
      }
    }
    if (changed) out = Buffer.from(lines.join("\n"), "utf8");
    // Cross-line backstop: fold/grep -o/read/od split the secret across
    // many lines; iconv interleaves NULs. Remove whitespace/control chars
    // from the whole output and re-check before releasing it.
    const whole = text.replace(/[^A-Za-z0-9_]+/g, "");
    const subseq = (needle, hay) => {
      let j = 0;
      for (let i = 0; i < hay.length && j < needle.length; i++) {
        if (hay[i] === needle[j]) j++;
      }
      return j === needle.length;
    };
    if (VS.some((v) => v && whole.includes(v)) ||
        VS.some((v) => v && subseq(v, whole))) {
      out = Buffer.from("[REDACTED]\n", "utf8");
    }
  } catch (_) {}
  return out;
}

function run(shell, args, useShell) {
  const child = spawn(shell, args, {
    cwd,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    shell: Boolean(useShell),
  });
  const out = [];
  const err = [];
  child.stdout.on("data", (d) => out.push(d));
  child.stderr.on("data", (d) => err.push(d));
  child.on("error", (e) => {
    process.stderr.write("LAB_REDACT_EXEC_ERROR\n");
    process.exit(1);
  });
  child.on("close", (code) => {
    const o = redactBuffer(Buffer.concat(out));
    const e = redactBuffer(Buffer.concat(err));
    if (o.length) process.stdout.write(o);
    if (e.length) process.stderr.write(e);
    process.exit(code === null ? 1 : code);
  });
}

// Keep the harness's shell syntax. Codex on Windows can issue PowerShell or
// cmd built-ins, while Claude Code/ccb usually issues POSIX shell commands.
const hasBash = spawnSync("bash", ["-lc", "true"], { stdio: "ignore" }).status === 0;
const isWin = process.platform === "win32";
const looksPowerShell = /\b(?:Get-Content|Get-ChildItem|Select-String|Set-Content|New-Item|Remove-Item|Copy-Item|Move-Item|Test-Path|Out-File|Where-Object|ForEach-Object|Get-Item|Get-Location)\b/i.test(cmd);
const looksCmd = /^\s*(?:type|dir|findstr|where|more|copy|move|del|ren|chcp|set)\b/i.test(cmd);
if (isWin && looksPowerShell) {
  run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd], false);
} else if (isWin && looksCmd) {
  run(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", cmd], true);
} else if (hasBash) {
  run("bash", ["-lc", cmd], false);
} else {
  run(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", cmd], true);
}
