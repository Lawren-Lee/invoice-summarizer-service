// Shared projection/detection core for the local v3 prototype.
// No Docker; same-user hooks/plugins are best-effort, not an OS boundary.
const fs = require("node:fs");
const path = require("node:path");

const ASSIGN = /^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(["']?)([^"'\r\n]*)(\4)(\s*(?:#.*)?)$/;
const PEM = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g;
const SENSITIVE_KEY = /(?:api[_-]?key|access[_-]?key|secret|password|passwd|pwd|credential|auth[_-]?token|(?:^|_)token(?:_|$)|database[_-]?url|connection[_-]?string)/i;
const PROVIDER = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:sk|ghp|github_pat)[_-][A-Za-z0-9_-]{16,}\b|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const URI = /[a-z][a-z0-9+.-]*:\/\/([^\s/@:]+):([^\s/@]+)@/gi;

function entropy(s) {
  if (!s) return 0;
  return -Array.from(new Set(s)).reduce((a, c) => {
    const p = s.split(c).length - 1;
    return a + (p / s.length) * Math.log2(p / s.length);
  }, 0);
}

function defaultSchema() {
  return {
    TIMEOUT: { type: "int", min: 1, max: 600 },
    MAX_RETRIES: { type: "int", min: 0, max: 10 },
    API_BASE_URL: { type: "url" },
    AWS_REGION: { type: "regex", pattern: "^[a-z]{2}-[a-z]+-[0-9]$" },
    base_url: { type: "url" },
    timeout: { type: "int", min: 1, max: 600 },
    retries: { type: "int", min: 0, max: 10 },
  };
}

function safeValue(key, value, schema) {
  const rule = (schema || {})[key];
  if (!rule) return false;
  if (rule.type === "int") {
    if (!/^\d+$/.test(String(value).trim())) return false;
    const n = Number(value);
    return n >= (rule.min ?? -Infinity) && n <= (rule.max ?? Infinity);
  }
  if (rule.type === "regex") {
    try { return new RegExp(rule.pattern).test(String(value).trim()); }
    catch (_) { return false; }
  }
  if (rule.type === "url") {
    try {
      const u = new URL(String(value).trim());
      if (!["http:", "https:"].includes(u.protocol)) return false;
      if (u.username || u.password) return false;
      if(u.search || u.hash)return false;
      if(rule.allowed_hosts && !rule.allowed_hosts.includes(u.hostname))return false;
      if(rule.allowed_paths && !rule.allowed_paths.includes(u.pathname))return false;
      for (const [k, v] of u.searchParams) {
        if (SENSITIVE_KEY.test(k) || SENSITIVE_KEY.test(v) || /secret|token|key|password|credential/i.test(v)) return false;
      }
      return true;
    } catch (_) { return false; }
  }
  return false;
}

function globalProfile(manifest) {return manifest.protection_profile || 'relations';}
function globalStructured(rel) {
  const ext=path.extname(rel).toLowerCase();
  return ['.env','.ini','.cfg','.json','.yaml','.yml','.toml','.py','.csv'].includes(ext) || path.basename(rel).startsWith('.env');
}
function isSensitive(rel, manifest) {
  if(globalProfile(manifest)==='global_strict')return true;
  if(globalProfile(manifest)==='global_objects' && globalStructured(rel))return true;
  const dirs = (manifest.sensitive_dirs || ["config"]).map((d) => String(d).replace(/\\/g, "/").replace(/\/$/, ""));
  const normal=s=>process.platform==="win32"?s.toLowerCase():s;
  const r = normal(String(rel || "").replace(/\\/g, "/"));
  const files=(manifest.sensitive_files||[]).map(x=>normal(String(x).replace(/\\/g,"/")));
  return files.includes(r) || dirs.some((d) => r === normal(d) || r.startsWith(normal(d) + "/"));
}

function legacyContent(text, rel, manifest, discovered) {
  const mode = manifest.mode || "projection";
  const schema = { ...defaultSchema(), ...(manifest.safe_schema || {}) };
  const known = (manifest.known_values || []).filter(Boolean);
  const vals = Array.from(new Set([...(discovered || []), ...known])).filter(Boolean);
  let out = String(text || "");
  const found = [];
  let changed = false;
  const sensitive = mode !== "content" && isSensitive(rel, manifest);

  const redactValue = (v) => {
    if (!v) return v;
    found.push(v);
    return "[REDACTED]";
  };

  if (sensitive) {
    const lines = out.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(ASSIGN);
      if (!m) continue;
      const key = m[2];
      const value = m[5];
      if (safeValue(key, value, schema)) continue;
      const red = redactValue(value);
      if (red !== value) {
        lines[i] = m[1] + key + m[3] + m[4] + red + m[4] + m[7];
        changed = true;
      }
    }
    out = lines.join("\n");
  }

  const replaceSpan = (start, end, label) => {
    const v = out.slice(start, end);
    if (!v) return;
    found.push(v);
    out = out.slice(0, start) + "[REDACTED]" + out.slice(end);
    changed = true;
  };

  if (PEM.test(out)) {
    PEM.lastIndex = 0;
    out = out.replace(PEM, (m) => {
      const parts = m.split(/\r?\n/);
      found.push(m);
      changed = true;
      return parts[0] + "\n[REDACTED]\n" + parts[parts.length - 1];
    });
  }

  for (const v of vals) {
    if (!v) continue;
    if (out.includes(v)) {
      out = out.split(v).join("[REDACTED]");
      changed = true;
    }
  }

  if (mode !== "B") {
    PROVIDER.lastIndex = 0;
    out = out.replace(PROVIDER, (m) => { found.push(m); changed = true; return "[REDACTED]"; });
    URI.lastIndex = 0;
    out = out.replace(URI, (m, user, pass) => {
      found.push(pass);
      changed = true;
      return m.replace(user + ":" + pass + "@", user + ":[REDACTED]@");
    });
    const lines = out.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(ASSIGN);
      if (!m) continue;
      const key = m[2], value = m[5];
      if (!value) continue;
      if (!safeValue(key, value, schema) && (SENSITIVE_KEY.test(key) || SENSITIVE_KEY.test(value))) {
        lines[i] = m[1] + key + m[3] + m[4] + "[REDACTED]" + m[4] + m[7];
        found.push(value); changed = true;
      }
    }
    out = lines.join("\n");
    const tokens = out.match(/(?<![A-Za-z0-9_])[A-Za-z0-9_+/=-]{24,}(?![A-Za-z0-9_])/g) || [];
    for (const t of tokens) {
      if (t === "[REDACTED]") continue;
      const charset = /^[0-9a-fA-F]+$/.test(t) ? 3.5 : /^[A-Za-z0-9+/=]+$/.test(t) ? 4.1 : 4.3;
      if (entropy(t) >= charset && !safeValue("API_BASE_URL", t, schema)) {
        // High-entropy values outside safe constraints are conservative.
        out = out.split(t).join("[REDACTED]");
        found.push(t); changed = true;
      }
    }
  }

  return { text: out, changed, labels: sensitive ? ["sensitive-region"] : [], discovered: found };
}

// v3.2: structured region projection; unparsed sensitive text is withheld.
// This is schema-based declassification, NOT arbitrary information-flow control.
function scopedSchema(manifest) {return manifest.schema_mode==='file-object';}
function schemaFor(rel, manifest) {
  const key=String(rel).replace(/\\/g,'/');
  const local=(manifest.safe_schema_by_file || {})[key] || {};
  if(scopedSchema(manifest))return {...local};
  return {...defaultSchema(),...(manifest.safe_schema || {}),...local};
}
function fieldKey(parts,schema,scoped) {
  if(!scoped){const dotted=parts.join('.');return Object.hasOwn(schema,dotted)?dotted:parts.at(-1);}
  const pointer=parts.length?'/'+parts.map(k=>String(k).replace(/~/g,'~0').replace(/\//g,'~1')).join('/'):'';
  if(Object.hasOwn(schema,pointer))return pointer;
  return parts.length===1 && /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(parts[0]) && Object.hasOwn(schema,parts[0])?parts[0]:null;
}

function regionProject(text, rel, manifest, discovered) {
  text = String(text || "");
  const mode = manifest.mode || "projection";
  if (mode === "plain") return {text, changed:false, labels:[], discovered:[]};
  const schema = schemaFor(rel, manifest);
  const sensitive = mode !== "content" && isSensitive(rel, manifest);
  const found = [];
  const hide = value => {if(value !== "" && value !== null && value !== undefined)found.push(String(value));return "[REDACTED]";};
  const withheld = reason => ({text:"# [WITHHELD: " + reason + "]\n", changed:true,
    labels:["sensitive-region", "unsupported-format"],discovered:[]});
  let out = text;
  if (sensitive) {
    const ext = path.basename(rel).startsWith(".env") ? ".env" : path.extname(rel).toLowerCase();
    if (ext === ".json") {
      let obj;try{obj=JSON.parse(text);}catch{return withheld("invalid JSON");}
      function walk(v, parts=[]) {
        if(Array.isArray(v))return v.map((x,i)=>walk(x,[...parts,String(i)]));
        if(v!==null && typeof v==="object")return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,walk(x,[...parts,k])]));
        const key=fieldKey(parts,schema,scopedSchema(manifest));
        const rule=key===null?undefined:schema[key];
        const typeOK=rule && (rule.type!=="int" || typeof v==="number");
        return typeOK && safeValue(key,String(v),schema)?v:hide(v);
      }
      out=JSON.stringify(walk(obj),null,2)+"\n";
    } else if (ext === ".py") {
      const {spawnSync}=require("node:child_process");
      const helper=path.join(__dirname,"v31_python_project.py");
      const python=manifest.python_executable || (process.platform==="win32"?"python":"python3");
      const invoke=body=>{
        const p=spawnSync(python,[helper],{input:JSON.stringify(body),encoding:"utf8",timeout:5000,maxBuffer:4e6});
        if(p.status!==0)throw Error();return JSON.parse(p.stdout);
      };
      try{
        const parsed=invoke({action:"parse",text,top_level_only:scopedSchema(manifest)});
        const allowed=Object.fromEntries(Object.entries(parsed.assigned).filter(([k,v])=>
          (schema[k]?.type!=="int" || typeof v==="number") && safeValue(k,String(v),schema)));
        const p=invoke({action:"project",text,allowed,public_metadata:manifest.public_metadata || [],top_level_only:scopedSchema(manifest)});out=p.text;found.push(...p.discovered);
      }catch{return withheld("Python projection unavailable or invalid");}
    } else if (['.csv','.toml'].includes(ext)) {
      const {spawnSync}=require('node:child_process');
      const python=manifest.python_executable || (process.platform==='win32'?'python':'python3');
      const r=spawnSync(python,[path.join(__dirname,'v33_formats.py')],{
        input:JSON.stringify({text,format:ext.slice(1),schema,scoped:scopedSchema(manifest)}),encoding:'utf8',timeout:5000,maxBuffer:4e6});
      if(r.status!==0)return withheld('structured format unavailable or invalid');
      try {const result=JSON.parse(r.stdout);out=result.text;found.push(...result.discovered);}
      catch{return withheld('structured format projection failed');}
    } else if ([".env",".cfg",".ini",".txt",".md",".yaml",".yml",""].includes(ext)) {
      const yaml=[".yaml",".yml"].includes(ext);
      const lines=[];let section=null;const yamlParents=[];
      for(const line of text.split(/\r?\n/)) {
        if(!line.trim()){lines.push("");continue;}
        if(/^\s*[#;]/.test(line)){lines.push("# [COMMENT WITHHELD]");continue;}
        if(!yaml && /^\s*\[[A-Za-z0-9_.-]+\]\s*$/.test(line)){section=line.trim().slice(1,-1);lines.push(line);continue;}
        const re=yaml?/^(\s*)([A-Za-z_][A-Za-z0-9_.-]*)(\s*:\s*)(.*)$/:/^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/;
        const m=line.match(re);if(!m)return withheld("unparsed sensitive text");
        let raw=m[4].trim();let parts;
        if(yaml){
          if(m[1].includes('\t'))return withheld('tab indentation unsupported');
          const indent=m[1].length;
          while(yamlParents.length && yamlParents.at(-1).indent>=indent)yamlParents.pop();
          parts=[...yamlParents.map(x=>x.key),m[2]];
          if(!raw){yamlParents.push({indent,key:m[2]});lines.push(line);continue;}
        }else parts=section?[section,m[2]]:[m[2]];
        // Deliberately support a scalar-only YAML subset. Reject complex YAML.
        if(yaml && /^[>|&*!\[{\-]/.test(raw))return withheld("complex YAML requires an approved parser");
        let value,quote="";
        if(raw.startsWith('"')||raw.startsWith("'")){
          quote=raw[0];const end=raw.indexOf(quote,1);
          if(end<0 || (raw.slice(end+1).trim() && !raw.slice(end+1).trim().startsWith("#")))return withheld("invalid quoted scalar");
          if(quote==='"'){try{value=JSON.parse(raw.slice(0,end+1));}catch{return withheld("unsupported escaped scalar");}}
          else value=raw.slice(1,end);
        }else value=raw.replace(/\s+#.*$/,"").trim();
        const key=fieldKey(parts,schema,scopedSchema(manifest));
        const safe=key!==null && safeValue(key,value,schema);
        const visible=safe?value:hide(value);
        // Retain quoting for textual values; opaque placeholders remain valid scalars.
        lines.push(m[1]+m[2]+m[3]+(quote?quote+visible+quote:visible));
      }
      out=lines.join("\n");
    } else return withheld("unsupported sensitive file type");
  }
  // Sink backstop also runs outside labelled regions. Known values remain protected.
  const content=legacyContent(out,rel,{...manifest,mode:"content"},discovered);
  found.push(...content.discovered);
  return {text:content.text,changed:content.text!==text,labels:sensitive?["sensitive-region"]:[],
    discovered:Array.from(new Set(found.filter(v=>v && v!=="[REDACTED]")))};
}

// Every read is evaluated at use time. Public files require explicit owner approval
// of exact bytes; extension/name/content alone never auto-declassifies prose.
function projectText(text, rel, manifest, discovered) {
  text=String(text || '');
  const profile=globalProfile(manifest);
  if((manifest.mode || 'projection')==='content' || profile==='relations')
    return regionProject(text,rel,manifest,discovered);
  const approval=(manifest.public_files || {})[String(rel).replace(/\\/g,'/')];
  const hash=require('node:crypto').createHash('sha256').update(text).digest('hex');
  if(approval && approval===hash)
    return regionProject(text,rel,{...manifest,mode:'content'},discovered);
  const ext=path.extname(rel).toLowerCase();
  if(profile==='global_objects' && !globalStructured(rel) && ['.md','.txt',''].includes(ext)) {
    const found=[];
    // Object coverage only: unknown prose/inline values stay visible deliberately.
    const out=text.split(/\r?\n/).map(line=>{
      if(!/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=/.test(line))return line;
      const r=regionProject(line,rel,{...manifest,protection_profile:'global_strict'},[]);
      found.push(...r.discovered);return r.text;
    }).join('\n');
    const backstop=regionProject(out,rel,{...manifest,mode:'content'},discovered);
    return {...backstop,changed:backstop.text!==text,labels:['partial-assignment-view'],discovered:[...found,...backstop.discovered]};
  }
  return regionProject(text,rel,manifest,discovered);
}

function matchesPattern(pattern, line) {
  if (!pattern) return false;
  let p = String(pattern), flags = "i";
  for (const f of ["i", "m", "s"]) {
    const token = "(?" + f + ")";
    if (p.includes(token)) { if (!flags.includes(f)) flags += f; p = p.split(token).join(""); }
  }
  try { return new RegExp(p, flags).test(line); }
  catch (_) { return String(line).toLowerCase().includes(String(pattern).toLowerCase()); }
}

module.exports = { ASSIGN, PEM, SENSITIVE_KEY, PROVIDER, URI, entropy, defaultSchema, safeValue, isSensitive, projectText, matchesPattern, schemaFor, globalProfile, globalStructured, fieldKey, scopedSchema };
