// One-shot structured job runner. Projection precedes every supported operation.
'use strict';
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {spawnSync}=require('node:child_process');
const engine=require('./v32_engine.js'),core=require('./v3_core.js');
function execute(ctx,action){
  let v;
  try{
    v=engine.view(ctx);let output='',status=0;
    const read=rel=>fs.readFileSync(path.join(v.root,rel),'utf8');
    if(action.kind==='cat')output=action.paths.map(read).join('');
    else if(action.kind==='pwd')output='[PROJECTED_WORKSPACE]\n';
    else if(action.kind==='list')output=fs.readdirSync(path.join(v.root,action.path)).sort().join('\n')+'\n';
    else if(action.kind==='search'){
      const needle=action.insensitive?action.pattern.toLowerCase():action.pattern;
      let count=0;
      for(const rel of engine.files(ctx)){
        if(action.path && rel!==action.path && !rel.startsWith(action.path+'/'))continue;
        const lines=read(rel).split(/\r?\n/),selected=new Set();
        for(let i=0;i<lines.length;i++){
          if((action.insensitive?lines[i].toLowerCase():lines[i]).includes(needle)){
            for(let j=Math.max(0,i-action.context);j<=Math.min(lines.length-1,i+action.context);j++)selected.add(j);
          }
        }
        for(const i of selected){output+=rel+':'+(action.numbers?(i+1)+':':'')+lines[i]+'\n';if(++count>10000)throw Error('V32_SEARCH_OUTPUT_BUDGET');}
      }
    }else if(action.kind==='owner-test'){
      // Optional trusted-owner compatibility mode, NOT an OS sandbox.
      // Repository dependencies run as the same user; disable for hostile code.
      const home=fs.mkdtempSync(path.join(os.tmpdir(),'v31-test-home-'));
      try{
        const env={};for(const k of ['PATH','SystemRoot','WINDIR','COMSPEC','PATHEXT','LANG','LC_ALL'])if(process.env[k])env[k]=process.env[k];
        Object.assign(env,{HOME:home,USERPROFILE:home,TEMP:home,TMP:home,TMPDIR:home,PYTHONDONTWRITEBYTECODE:'1',PYTHONNOUSERSITE:'1'});
        const p=spawnSync(action.argv[0],action.argv.slice(1),{cwd:['global_objects','global_strict'].includes(ctx.m.protection_profile)?ctx.repo:v.root,env,shell:false,encoding:'utf8',timeout:30000,maxBuffer:1_000_000});
        if(p.error)throw Error('V32_OWNER_TEST_FAILED');
        status=p.status??1;
        output=['global_objects','global_strict'].includes(ctx.m.protection_profile)?JSON.stringify({owner_test_completed:true,status})+'\n':String(p.stdout||'')+String(p.stderr||'');
      }finally{fs.rmSync(home,{recursive:true,force:true});}
    }else throw Error('V32_JOB_ACTION');
    // Additional literal/pattern backstop, not the primary protection mechanism.
    if(!(action.kind==='owner-test' && ['global_objects','global_strict'].includes(ctx.m.protection_profile)))
      output=core.projectText(output,'output.txt',{...ctx.m,mode:'content'},v.discovered).text;
    engine.audit(ctx,'job_completed',{kind:action.kind,status});return {output,status};
  }finally{if(v)fs.rmSync(v.root,{recursive:true,force:true});}
}
if(require.main===module){
  try{
    const argv=process.argv.slice(2);
    if(argv.length!==4||argv[0]!=='--manifest'||argv[2]!=='--job')throw Error('V32_STRUCTURED_JOB_REQUIRED');
    const {ctx,action}=engine.takeJob(argv[1],argv[3]),result=execute(ctx,action);
    process.stdout.write(result.output);process.exitCode=result.status;
  }catch(e){process.stderr.write((/^V(?:32|33|35|36)_/.test(e.message)?e.message:'V32_JOB_REJECTED')+'\n');process.exitCode=2;}
}
module.exports={execute};
