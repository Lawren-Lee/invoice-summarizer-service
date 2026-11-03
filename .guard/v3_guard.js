// v3.2 native Hook adapter; all policy decisions live in v32_engine.js.
'use strict';
const engine=require('./v32_engine.js');
const agent=process.argv[3]||'ccb';
// Installer passes absolute repository/policy paths. Never derive policy root from tool cwd.
const repo=process.argv[4],manifest=process.argv[5];
let raw='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>raw+=c);
process.stdin.on('end',()=>{
  let ctx,data;
  const emit=obj=>process.stdout.write(JSON.stringify(obj));
  const deny=reason=>{
    if(ctx)engine.audit(ctx,'deny',{agent,tool:String(data?.tool_name||''),reason});
    if(agent==='gemini'){process.stderr.write(reason+'\n');process.exitCode=2;return;}
    emit({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:reason},
      ...(agent==='qwen'?{decision:'deny',reason}:{})});
  };
  try{
    data=JSON.parse(raw);ctx=engine.context(repo,manifest);
    const event=data.hook_event_name;
    if(['PostToolUse','AfterTool'].includes(event)){
      engine.audit(ctx,'tool_output',{agent,tool:data.tool_name});
      const result=engine.applyEdit(ctx,{...data,agent});
      if(result.block)emit({decision:'block',reason:result.reason});
      return;
    }
    if(!['PreToolUse','BeforeTool'].includes(event))return;
    const result=engine.decide(ctx,data.tool_name,data.tool_input||{});
    engine.audit(ctx,result.event,{agent,tool:data.tool_name});
    if(agent==='gemini')emit({hookSpecificOutput:{hookEventName:'BeforeTool',tool_input:result.input}});
    else emit({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'allow',updatedInput:result.input}});
  }catch(e){if(process.env.V32_DEBUG)process.stderr.write(String(e.stack||e)+"\n");deny(/^V(?:32|33|35|36)_/.test(e.message)?e.message:'V32_GUARD_ERROR');}
});
