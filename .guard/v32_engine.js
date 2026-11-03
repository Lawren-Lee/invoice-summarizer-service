// v3.2 shared decision engine. Same-UID best-effort mediation, not a sandbox.
// Read uses a stable projected view; Edit runs on that view; PostToolUse applies
// the validated edit back to the original file without exposing raw secrets.
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const core=require('./v3_core.js');
const EXCLUDE=new Set(['.git','.guard','.shadow','.claude','.qwen','.gemini','.opencode','__pycache__','node_modules','.venv','venv']);
const PATH_KEYS=['file_path','filePath','absolute_path','path'];
const VERSION='3.2';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const slash=x=>x.replace(/\\/g,'/');
function inside(root,p){const r=path.relative(root,p);return r==='' || (!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));}
function context(repo,manifestPath){
  repo=fs.realpathSync(repo);manifestPath=path.resolve(manifestPath||path.join(path.dirname(repo),'v3_manifest.json'));
  const bytes=fs.readFileSync(manifestPath),m=JSON.parse(bytes);
  if(m.version!==VERSION)throw Error('V32_POLICY_VERSION_REQUIRED');
  if(!['projection','content'].includes(m.mode))throw Error('V32_INVALID_MODE');
  if(!['relations','global_objects','global_strict'].includes(m.protection_profile||'relations'))throw Error('V33_INVALID_PROFILE');
  if(['3.5','3.6'].includes(m.experiment_version) && (m.schema_mode!=='file-object'||Object.keys(m.safe_schema||{}).length))throw Error('V35_SCOPED_SCHEMA_REQUIRED');
  if(m.experiment_version==='3.6' && !['zero','seeded'].includes(m.knowledge_mode))throw Error('V36_KNOWLEDGE_MODE_REQUIRED');
  if(m.knowledge_mode==='zero'){
    if(['anchors','known_values','known_fields','sensitive_dirs','sensitive_files','relation_evidence_hashes'].some(k=>m[k] && Object.keys(m[k]).length))throw Error('V36_ZERO_PRIOR_VIOLATION');
    if(m.region_strategy!=='none')throw Error('V36_ZERO_RELATION_EXPANSION');
  }
  const ctx={repo,manifestPath,m,policyHash:sha(bytes),caseRoot:path.dirname(manifestPath)};
  const known=[];
  for(const a of m.anchors||[]){
    const rel=canonical(ctx,a.path),text=fs.readFileSync(path.join(repo,rel),'utf8');
    let v;
    if(path.extname(rel)==='.json'){
      let o=JSON.parse(text);for(const k of a.field.split('.'))o=o?.[k];v=o;
    }else{
      const escaped=a.field.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
      const match=text.match(new RegExp('^\\s*(?:export\\s+)?'+escaped+'\\s*=\\s*(.*?)\\s*$','m'));
      if(match){v=match[1].replace(/\s+#.*$/,'').trim();if(/^(["']).*\1$/.test(v))v=v.slice(1,-1);}
    }
    if(v===undefined||String(v)==='')throw Error('V32_ANCHOR_NOT_RESOLVED');known.push(String(v));
  }
  ctx.m={...m,known_values:known};
  for(const [rel,hash] of Object.entries(m.relation_evidence_hashes||{})){
    canonical(ctx,rel);
    if(sha(fs.readFileSync(path.join(repo,rel)))!==hash)throw Error('V32_REGION_EVIDENCE_STALE_OWNER_REFRESH_REQUIRED');
  }
  // Existing filenames and path components are public metadata, not secret values.
  // Recompute so newly added files also go through the same global projection.
  if(['global_objects','global_strict'].includes(m.protection_profile)){
    const names=files(ctx);
    ctx.m.public_metadata=Array.from(new Set(names.flatMap(rel=>[rel,...rel.split('/')])));
  }
  if(m.usage_scan===true){
    const r=require('node:child_process').spawnSync(m.python_executable || (process.platform==='win32'?'python':'python3'),
      [path.join(__dirname,'v33_usage.py')],{input:JSON.stringify({repo}),encoding:'utf8',timeout:10000,maxBuffer:4e6});
    if(r.status!==0)throw Error('V33_USAGE_SCAN_FAILED');
    const candidates=JSON.parse(r.stdout);
    ctx.m.known_values=Array.from(new Set([...known,...candidates.values]));
    ctx.usage_evidence=candidates.evidence;
  }
  return ctx;
}
function canonical(ctx,target,{directory=false}={}){
  if(typeof target!=='string'||target.includes('\0'))throw Error('V32_PATH_REQUIRED');
  const abs=path.resolve(ctx.repo,target);
  if(!inside(ctx.repo,abs))throw Error('V32_OUTSIDE_REPOSITORY');
  let rel=slash(path.relative(ctx.repo,abs));
  // Only our named view prefixes map back; policy is applied again below.
  const shadow=rel.match(/^\.shadow\/(?:view-[a-f0-9]{24}|v32-read-[a-f0-9]{12})\/(.+)$/);
  if(shadow)rel=shadow[1];
  else if(rel==='.shadow'||rel.startsWith('.shadow/'))throw Error('V32_CONTROL_PATH');
  const parts=rel.split('/');
  if(parts.some(p=>EXCLUDE.has(p)||EXCLUDE.has(p.toLowerCase()))||rel==='opencode.json')throw Error('V32_CONTROL_PATH');
  const actual=path.join(ctx.repo,rel);let current=ctx.repo;
  for(const p of parts.filter(Boolean)){
    if(process.platform==='win32'&&(/[ .:]$/.test(p)||p.includes(':')))throw Error('V32_AMBIGUOUS_PATH');
    current=path.join(current,p);
    if(fs.existsSync(current)&&fs.lstatSync(current).isSymbolicLink())throw Error('V32_SYMLINK_UNSUPPORTED');
  }
  if(!fs.existsSync(actual))throw Error('V32_FILE_MISSING');
  const stat=fs.statSync(actual);
  if(stat.nlink>1&&stat.isFile())throw Error('V32_HARDLINK_UNSUPPORTED');
  if(directory?!stat.isDirectory():!stat.isFile())throw Error('V32_WRONG_PATH_TYPE');
  if(!inside(ctx.repo,fs.realpathSync(actual)))throw Error('V32_RESOLVED_PATH_OUTSIDE');
  return rel;
}
function files(ctx){
  const out=[];let total=0;
  function walk(dir){
    for(const e of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
      if(EXCLUDE.has(e.name)||EXCLUDE.has(e.name.toLowerCase())||e.name==='opencode.json')continue;
      const p=path.join(dir,e.name),rel=slash(path.relative(ctx.repo,p));
      if(e.isSymbolicLink())throw Error('V32_SYMLINK_UNSUPPORTED');
      if(e.isDirectory())walk(p);
      else if(e.isFile()){
        const st=fs.statSync(p);if(st.nlink>1)throw Error('V32_HARDLINK_UNSUPPORTED');
        total+=st.size;out.push(rel);
        if(out.length>(ctx.m.snapshot_max_files||2000)||total>(ctx.m.snapshot_max_bytes||20_000_000)||st.size>1_000_000)throw Error('V32_SNAPSHOT_BUDGET');
      }
    }
  }walk(ctx.repo);return out;
}
function project(ctx,rel){
  const bytes=fs.readFileSync(path.join(ctx.repo,rel));
  let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{throw Error('V32_NON_UTF8_UNSUPPORTED');}
  if(text.includes('\0'))throw Error('V32_BINARY_UNSUPPORTED');
  return core.projectText(text,rel,ctx.m,[]);
}
function readRoot(ctx){return path.join(ctx.repo,'.shadow','v32-read-'+ctx.policyHash.slice(0,12));}
function metaPath(ctx,rel){return path.join(readRoot(ctx),'.meta',rel+'.json');}
function jobPath(ctx,rel){return path.join(ctx.caseRoot,'.v31_jobs','edit-'+sha(rel).slice(0,20)+'.json');}
function key(ctx){return fs.readFileSync(path.join(ctx.caseRoot,'.v31_control.key'));}
function sign(ctx,body){return crypto.createHmac('sha256',key(ctx)).update(JSON.stringify(body)).digest('hex');}
function atomicWrite(file,text,mode=0o600){
  const tmp=file+'.v32-tmp-'+process.pid+'-'+crypto.randomBytes(4).toString('hex');
  fs.mkdirSync(path.dirname(file),{recursive:true});
  fs.writeFileSync(tmp,text,{encoding:'utf8',mode});
  try{fs.renameSync(tmp,file);}
  catch(_){
    try{fs.copyFileSync(tmp,file);fs.unlinkSync(tmp);}
    catch(e){try{fs.unlinkSync(tmp);}catch{}throw e;}
  }
}
function view(ctx,rels=files(ctx),{stable=false}={}){
  const root=stable?readRoot(ctx):path.join(ctx.repo,'.shadow','view-'+crypto.randomBytes(12).toString('hex'));
  const projected=rels.map(rel=>[rel,project(ctx,rel)]);
  fs.mkdirSync(root,{recursive:true});
  for(const [rel,p] of projected){const dest=path.join(root,rel);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,p.text);}
  return {root,discovered:projected.flatMap(x=>x[1].discovered)};
}
function viewForRead(ctx,rel){
  const p=project(ctx,rel),root=readRoot(ctx),shadow=path.join(root,rel);
  fs.mkdirSync(path.dirname(shadow),{recursive:true});
  fs.writeFileSync(shadow,p.text,'utf8');
  const meta={version:VERSION,rel,policyHash:ctx.policyHash,
    realSha:sha(fs.readFileSync(path.join(ctx.repo,rel))),projectedSha:sha(p.text),at:Date.now()};
  atomicWrite(metaPath(ctx,rel),JSON.stringify(meta));
  try{fs.unlinkSync(jobPath(ctx,rel));}catch(_){}
  return {root,shadow,projected:p,meta};
}
function readMeta(ctx,rel){
  try{const m=JSON.parse(fs.readFileSync(metaPath(ctx,rel),'utf8'));
    if(m.version!==VERSION||m.rel!==rel||m.policyHash!==ctx.policyHash)return null;return m;}
  catch(_){return null;}
}
function paths(input,p){const o={...input};for(const k of PATH_KEYS)if(k in o)o[k]=p;
  if(!PATH_KEYS.some(k=>k in o))o.file_path=p;return o;}
function tokenize(command){
  if(typeof command!=='string'||/[\r\n;&|<>`$%\0]/.test(command))throw Error('V32_SHELL_SYNTAX_DENIED');
  const tokens=command.match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s"']+/g)||[];
  if(tokens.join(' ').replace(/\s/g,'')!==command.trim().replace(/\s/g,''))throw Error('V32_SHELL_QUOTES_DENIED');
  return tokens.map(t=>/^['"]/.test(t)?t.slice(1,-1):t);
}
function safeOperand(s){if(path.isAbsolute(s)||s.includes('\\')||s.split('/').includes('..')||s.includes(':'))throw Error('V32_UNSAFE_OPERAND');return s;}
function commandAction(ctx,command){
  const argv=tokenize(command),exe=argv.shift();
  if(['cat','type'].includes(exe)){
    if(!argv.length||argv.some(x=>x.startsWith('-')))throw Error('V32_CAT_ARGUMENTS');
    return {kind:'cat',paths:argv.map(x=>canonical(ctx,safeOperand(x)))};
  }
  if(['ls','dir','pwd'].includes(exe)){
    if(exe==='pwd'&&argv.length)throw Error('V32_PWD_ARGUMENTS');
    if(argv.length>1)throw Error('V32_LIST_ARGUMENTS');
    const rel=canonical(ctx,safeOperand(argv[0]||'.'),{directory:true});return {kind:exe==='pwd'?'pwd':'list',path:rel};
  }
  if(['rg','grep'].includes(exe)){
    let insensitive=false,numbers=false,context=0;
    while(argv[0]?.startsWith('-')){
      const flag=argv.shift();if(flag==='-i')insensitive=true;else if(flag==='-n')numbers=true;
      else if(['-C','--context'].includes(flag)){context=Number(argv.shift());if(!Number.isInteger(context)||context<0||context>20)throw Error('V32_SEARCH_CONTEXT');}
      else throw Error('V32_SEARCH_FLAG_UNSUPPORTED');
    }
    if(argv.length<1||argv.length>2)throw Error('V32_SEARCH_ARGUMENTS');
    const pattern=argv.shift();if(pattern.length>200)throw Error('V32_PATTERN_TOO_LONG');
    let rel=safeOperand(argv[0]||'.');const abs=path.resolve(ctx.repo,rel);
    rel=canonical(ctx,rel,{directory:fs.existsSync(abs)&&fs.statSync(abs).isDirectory()});
    return {kind:'search',pattern,insensitive,numbers,context,path:rel};
  }
  const full=[exe,...argv];
  const test=(ctx.m.owner_test_commands||[]).find(t=>JSON.stringify(t.argv)===JSON.stringify(full));
  if(test&&ctx.m.allow_host_tests===true){
    if(['global_objects','global_strict'].includes(ctx.m.protection_profile)){
      for(const [rel,hash] of Object.entries(ctx.m.owner_runtime_hashes||{})){
        canonical(ctx,rel);if(sha(fs.readFileSync(path.join(ctx.repo,rel)))!==hash)throw Error('V33_OWNER_RUNTIME_CHANGED');
      }
    }
    for(const [rel,hash] of Object.entries(test.hashes||{})){
      canonical(ctx,rel);if(sha(fs.readFileSync(path.join(ctx.repo,rel)))!==hash)throw Error('V32_OWNER_TEST_CHANGED');
    }
    return {kind:'owner-test',argv:full};
  }
  throw Error('V32_UNSUPPORTED_SHELL_COMMAND');
}
function makeJob(ctx,action){
  const nonce=crypto.randomBytes(16).toString('hex'),jobs=path.join(ctx.caseRoot,'.v31_jobs');
  fs.mkdirSync(jobs,{recursive:true});
  const body={repo:ctx.repo,manifest:ctx.manifestPath,policyHash:ctx.policyHash,action,expires:Date.now()+60000,nonce};
  const raw=JSON.stringify(body),mac=crypto.createHmac('sha256',key(ctx)).update(raw).digest('hex');
  fs.writeFileSync(path.join(jobs,nonce+'.json'),JSON.stringify({body,mac}),{flag:'wx',mode:0o600});
  const wrapper=path.join(__dirname,'v3_redact.js');
  const quote=s=>{s=slash(s);if(/["`$%\r\n]/.test(s))throw Error('V32_UNSUPPORTED_INSTALL_PATH');return '"'+s+'"';};
  return 'node '+quote(wrapper)+' --manifest '+quote(ctx.manifestPath)+' --job '+nonce;
}
function takeJob(manifest,nonce){
  if(!/^[a-f0-9]{32}$/.test(nonce))throw Error('V32_BAD_JOB_ID');
  const caseRoot=path.dirname(path.resolve(manifest)),file=path.join(caseRoot,'.v31_jobs',nonce+'.json');
  const raw=fs.readFileSync(file);fs.unlinkSync(file);
  const {body,mac}=JSON.parse(raw);
  const expected=crypto.createHmac('sha256',fs.readFileSync(path.join(caseRoot,'.v31_control.key'))).update(JSON.stringify(body)).digest('hex');
  if(typeof mac!=='string'||mac.length!==64||!crypto.timingSafeEqual(Buffer.from(mac),Buffer.from(expected)))throw Error('V32_JOB_SIGNATURE');
  const ctx=context(body.repo,manifest);
  if(body.nonce!==nonce||path.resolve(body.manifest)!==path.resolve(manifest)||body.policyHash!==ctx.policyHash||body.expires<Date.now())throw Error('V32_JOB_EXPIRED_OR_POLICY_CHANGED');
  return {ctx,action:body.action};
}
function immutableEnv(ctx,rel,text){
  const schema=core.schemaFor(rel,ctx.m);let parsed=true,section=null;
  const out=text.split(/\r?\n/).map(line=>{
    if(!line.trim()||/^\s*[#;]/.test(line))return line;
    if(/^\s*\[[A-Za-z0-9_.-]+\]\s*$/.test(line)){section=line.trim().slice(1,-1);return line;}
    const m=line.match(core.ASSIGN);if(!m){parsed=false;return line;}
    const key=core.fieldKey(section?[section,m[2]]:[m[2]],schema,core.scopedSchema(ctx.m));
    return key!==null && core.safeValue(key,m[5],schema)?m[1]+m[2]+m[3]+m[4]+'<SAFE>'+m[4]+m[7]:line;
  }).join('\n');return {out,parsed};
}

function lockEdit(ctx){
  const lock=path.join(ctx.caseRoot,'.v31_jobs','edit.lock');
  fs.mkdirSync(path.dirname(lock),{recursive:true});
  try{const fd=fs.openSync(lock,'wx',0o600);fs.writeFileSync(fd,String(process.pid));fs.closeSync(fd);}
  catch(_){
    try{if(Date.now()-fs.statSync(lock).mtimeMs>60000){fs.unlinkSync(lock);return lockEdit(ctx);}}catch{}
    throw Error('V32_EDIT_BUSY');
  }
  return lock;
}
function unlockEdit(lock){try{fs.unlinkSync(lock);}catch(_){}}
function decide(ctx,tool,input){
  const t=String(tool).toLowerCase();input={...input};
  const target=()=>PATH_KEYS.map(k=>input[k]).find(x=>x!==undefined);
  if(['read','read_file'].includes(t)){
    const rel=canonical(ctx,target()),v=viewForRead(ctx,rel);
    return {input:paths(input,v.shadow),event:'projected_read'};
  }
  if(['grep','search','grep_search','search_file_content','glob','list','list_directory'].includes(t)){
    for(const keys of [['glob','include','pattern']]){
      for(const key of keys){
        if(['glob','list','list_directory'].includes(t)||key!=='pattern'){
          if(typeof input[key]==='string'&&(path.isAbsolute(input[key])||input[key].replace(/\\/g,'/').split('/').includes('..')))throw Error('V32_SEARCH_PATH_PATTERN');
        }
      }
    }
    const key=['path','dir_path','directory'].find(k=>input[k]!==undefined)||'path',raw=input[key]||'.';
    const abs=path.resolve(ctx.repo,raw);const rel=canonical(ctx,raw,{directory:fs.existsSync(abs)&&fs.statSync(abs).isDirectory()});
    const v=view(ctx);input[key]=path.join(v.root,rel);return {input,event:'projected_search'};
  }
  if(['bash','shell','command','run_shell_command'].includes(t)){
    const key='cmd' in input?'cmd':'command';const action=commandAction(ctx,input[key]);
    input[key]=makeJob(ctx,action);return {input,event:'projected_command'};
  }
  if(['edit','edit_file','replace'].includes(t)){
    const targetPath=target(),rel=canonical(ctx,targetPath);
    if(Object.hasOwn(ctx.m.relation_evidence_hashes||{},rel))throw Error('V32_REGION_EVIDENCE_EDIT_REQUIRES_OWNER_REFRESH');
    if((ctx.m.protected_edit_paths||['tests/']).some(p=>rel===p.replace(/\/$/,'')||rel.startsWith(p.replace(/\/$/,'')+'/')))throw Error('V32_PROTECTED_EDIT');
    const realPath=path.join(ctx.repo,rel),root=readRoot(ctx),shadow=path.join(root,rel);
    const realAbs=path.resolve(ctx.repo,targetPath),rootAbs=path.resolve(root);
    if(!inside(rootAbs,realAbs)&&path.resolve(realPath)!==realAbs)throw Error('V32_READ_REQUIRED');
    const meta=readMeta(ctx,rel);if(!meta)throw Error('V32_READ_REQUIRED');
    if(!fs.existsSync(shadow))throw Error('V32_READ_REQUIRED');
    const old=input.old_string??input.old_str,newText=input.new_string??input.new_str;
    if(typeof old!=='string'||!old||typeof newText!=='string'||input.replace_all)throw Error('V32_UNSUPPORTED_EDIT');
    const before=fs.readFileSync(realPath,'utf8'),projected=fs.readFileSync(shadow,'utf8');
    if(sha(before)!==meta.realSha||sha(projected)!==meta.projectedSha)throw Error('V32_STALE_VIEW');
    if(projected.split(old).length!==2)throw Error('V32_EDIT_NOT_VISIBLE_IN_VIEW');
    if(before.split(old).length!==2)throw Error('V32_EDIT_REQUIRES_UNIQUE_REAL_TEXT');
    if(newText.includes('[REDACTED]')||ctx.m.known_values.some(x=>newText.includes(x)))throw Error('V32_SECRET_INSERTION');
    const after=before.replace(old,newText),expectedShadow=projected.replace(old,newText);
    if(expectedShadow===projected)throw Error('V32_EMPTY_EDIT');
    if(core.isSensitive(rel,ctx.m)){
      if(!['.env','.ini','.cfg'].includes(path.extname(rel)))throw Error('V32_SENSITIVE_EDIT_FORMAT_UNSUPPORTED');
      const a=immutableEnv(ctx,rel,before),b=immutableEnv(ctx,rel,after);
      if(!a.parsed||!b.parsed||a.out!==b.out)throw Error('V32_PROTECTED_FIELDS_CHANGED');
    }
    const body={version:VERSION,rel,policyHash:ctx.policyHash,realSha:sha(before),projectedSha:sha(projected),
      expectedShadowSha:sha(expectedShadow),oldSha:sha(old),newSha:sha(newText),expires:Date.now()+60000,nonce:crypto.randomBytes(8).toString('hex')};
    const jp=jobPath(ctx,rel);
    try{
      const oldJob=JSON.parse(fs.readFileSync(jp,'utf8'));
      if(oldJob?.body?.expires>Date.now())throw Error('V32_EDIT_PENDING');
      fs.unlinkSync(jp);
    }catch(e){if(e.message==='V32_EDIT_PENDING')throw e;try{fs.unlinkSync(jp);}catch(_){}}
    fs.mkdirSync(path.dirname(jp),{recursive:true});
    fs.writeFileSync(jp,JSON.stringify({body,mac:sign(ctx,body)}),{flag:'wx',mode:0o600});
    return {input:paths(input,shadow),event:'safe_edit'};
  }
  if(['todowrite','todo_read','todoread'].includes(t))return {input,event:'metadata'};
  throw Error('V32_UNSUPPORTED_TOOL');
}
function applyEdit(ctx,data){
  const tool=String(data.tool_name||'').toLowerCase();
  if(!['edit','edit_file','replace'].includes(tool))return {ok:true,applied:false};
  const input=data.tool_input||{};
  const targetPath=PATH_KEYS.map(k=>input[k]).find(x=>x!==undefined);
  let rel;
  try{rel=canonical(ctx,targetPath);}catch(e){return {block:true,reason:e.message.startsWith('V32_')?e.message:'V32_EDIT_TARGET'};}
  const jp=jobPath(ctx,rel);let job;
  try{job=JSON.parse(fs.readFileSync(jp,'utf8'));}catch(_){return {ok:true,applied:false};}
  const body=job.body||{};
  const expected=sign(ctx,body);
  if(typeof job.mac!=='string'||job.mac.length!==64||!crypto.timingSafeEqual(Buffer.from(job.mac),Buffer.from(expected))){
    try{fs.unlinkSync(jp);}catch(_){}return {block:true,reason:'V32_EDIT_JOB_SIGNATURE'};
  }
  if(body.version!==VERSION||body.rel!==rel||body.policyHash!==ctx.policyHash||body.expires<Date.now()){
    try{fs.unlinkSync(jp);}catch(_){}return {block:true,reason:'V32_EDIT_JOB_EXPIRED'};
  }
  const resp=data.tool_response;
  if(resp&&(resp.is_error===true||resp.error||(typeof resp==='string'&&/^error/i.test(resp)))){
    try{fs.unlinkSync(jp);}catch(_){}return {ok:true,applied:false};
  }
  const old=input.old_string??input.old_str,newText=input.new_string??input.new_str;
  if(typeof old!=='string'||typeof newText!=='string'||sha(old)!==body.oldSha||sha(newText)!==body.newSha){
    try{fs.unlinkSync(jp);}catch(_){}return {block:true,reason:'V32_EDIT_INPUT_CHANGED'};
  }
  const realPath=path.join(ctx.repo,rel),shadow=path.join(readRoot(ctx),rel);
  let lock;
  try{
    lock=lockEdit(ctx);
    const before=fs.readFileSync(realPath,'utf8'),shadowText=fs.readFileSync(shadow,'utf8');
    if(sha(before)!==body.realSha)throw Error('V32_EDIT_STALE_REAL');
    if(sha(shadowText)!==body.expectedShadowSha)throw Error('V32_EDIT_VIEW_MISMATCH');
    if(before.split(old).length!==2)throw Error('V32_EDIT_REAL_MATCH_CHANGED');
    if(newText.includes('[REDACTED]')||ctx.m.known_values.some(x=>newText.includes(x)))throw Error('V32_SECRET_INSERTION');
    const after=before.replace(old,newText);
    if(core.isSensitive(rel,ctx.m)){
      const a=immutableEnv(ctx,rel,before),b=immutableEnv(ctx,rel,after);
      if(!a.parsed||!b.parsed||a.out!==b.out)throw Error('V32_PROTECTED_FIELDS_CHANGED');
    }
    const mode=fs.statSync(realPath).mode;
    atomicWrite(realPath,after,mode);
    const meta={version:VERSION,rel,policyHash:ctx.policyHash,realSha:sha(after),projectedSha:sha(shadowText),at:Date.now()};
    atomicWrite(metaPath(ctx,rel),JSON.stringify(meta));
    try{fs.unlinkSync(jp);}catch(_){}
    audit(ctx,'edit_applied',{agent:String(data.agent||''),tool:data.tool_name,path:rel});
    return {ok:true,applied:true};
  }catch(e){
    try{fs.unlinkSync(jp);}catch(_){}
    const reason=/^V32_/.test(e.message)?e.message:'V32_EDIT_APPLY_FAILED';
    audit(ctx,'edit_blocked',{agent:String(data.agent||''),tool:data.tool_name,path:rel,reason});
    return {block:true,reason};
  }finally{if(lock)unlockEdit(lock);}
}
function audit(ctx,event,extra={}){
  fs.appendFileSync(path.join(ctx.caseRoot,'v3_guard.raw.jsonl'),JSON.stringify({time:new Date().toISOString(),version:VERSION,event,policy_hash:ctx.policyHash,...extra})+'\n');
}
module.exports={context,canonical,files,project,view,viewForRead,readRoot,metaPath,jobPath,decide,applyEdit,commandAction,takeJob,audit,sha};
