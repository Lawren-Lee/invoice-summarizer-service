"""Small usage-guided scanner inspired by AssetHarvester's driver sinks.
Not a CodeQL/AssetHarvester reproduction. Bounded Python AST only, no execution.
Private values returned to guard memory; public evidence excludes raw values.
"""
import ast
import hashlib
import json
import os
import sys
from pathlib import Path

SKIP={'.git','.guard','.shadow','.claude','.qwen','.gemini','.opencode','node_modules','.venv','venv','__pycache__'}
DRIVERS={'psycopg2.connect','pymysql.connect','mysql.connector.connect','asyncpg.connect','aiomysql.connect','pymssql.connect'}
CREDENTIALS={'password','passwd','pwd'}


def discover(repo):
    repo=Path(repo).resolve();modules={};count=0;total=0;skipped=[]
    for folder,dirs,names in os.walk(repo,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in SKIP and not (Path(folder)/d).is_symlink())
        for name in sorted(names):
            if not name.endswith('.py'):continue
            p=Path(folder)/name
            if p.is_symlink():continue
            count+=1;total+=p.stat().st_size
            if count>2000 or total>8_000_000 or p.stat().st_size>1_000_000:raise ValueError('usage input budget')
            try:tree=ast.parse(p.read_text(encoding='utf-8'))
            except (SyntaxError,UnicodeError):skipped.append(p.relative_to(repo).as_posix());continue
            rel=p.relative_to(repo);module='.'.join(rel.with_suffix('').parts)
            if module.endswith('.__init__'):module=module[:-9]
            modules[module]={'tree':tree,'path':rel.as_posix(),'bindings':{},'aliases':{}}
    for module,m in modules.items():
        for n in m['tree'].body:
            if isinstance(n,ast.Import):
                for a in n.names:m['aliases'][a.asname or a.name.split('.')[0]]=a.name if a.asname else a.name.split('.')[0]
            elif isinstance(n,ast.ImportFrom) and n.level==0 and n.module:
                for a in n.names:m['aliases'][a.asname or a.name]=n.module+'.'+a.name
            elif isinstance(n,(ast.Assign,ast.AnnAssign)):
                targets=n.targets if isinstance(n,ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t,ast.Name):
                        m['bindings'][t.id]=None if t.id in m['bindings'] else n.value
    def qualify(node,m):
        if isinstance(node,ast.Name):return m['aliases'].get(node.id,node.id)
        if isinstance(node,ast.Attribute):
            base=qualify(node.value,m)
            return base+'.'+node.attr if base else None
    def evaluate(n,module,local,seen=frozenset()):
        if n is None or len(seen)>20:return None
        m=modules[module]
        if isinstance(n,ast.Constant) and isinstance(n.value,str):return n.value
        if isinstance(n,ast.Name):
            tag=(module,n.id)
            if tag in seen:return None
            if n.id in local:return evaluate(local[n.id],module,local,seen|{tag})
            if n.id in m['bindings']:return evaluate(m['bindings'][n.id],module,{},seen|{tag})
            q=m['aliases'].get(n.id,'')
            mod,_,name=q.rpartition('.')
            if mod in modules:return evaluate(modules[mod]['bindings'].get(name),mod,{},seen|{tag})
        if isinstance(n,ast.Attribute):
            q=qualify(n,m);mod,_,name=(q or '').rpartition('.')
            if mod in modules:return evaluate(modules[mod]['bindings'].get(name),mod,{},seen|{(mod,name)})
        if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add):
            a=evaluate(n.left,module,local,seen);b=evaluate(n.right,module,local,seen)
            if isinstance(a,str) and isinstance(b,str):return a+b
        if isinstance(n,ast.Subscript) and isinstance(n.value,ast.Dict) and isinstance(n.slice,ast.Constant):
            for k,v in zip(n.value.keys,n.value.values):
                if isinstance(k,ast.Constant) and k.value==n.slice.value:return evaluate(v,module,local,seen)
        return None
    values=set();evidence=[]
    for module,m in modules.items():
        scopes=[m['tree'],*[n for n in ast.walk(m['tree']) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))]]
        for scope in scopes:
            local={}
            # Function parameters may shadow module-level constants/imports.
            if isinstance(scope,(ast.FunctionDef,ast.AsyncFunctionDef)):
                for a in [*scope.args.posonlyargs,*scope.args.args,*scope.args.kwonlyargs]:local[a.arg]=None
            def walk(node):
                if node is not scope and isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):return
                if isinstance(node,(ast.Assign,ast.AnnAssign)) and scope is not m['tree']:
                    for t in node.targets if isinstance(node,ast.Assign) else [node.target]:
                        if isinstance(t,ast.Name):local[t.id]=node.value
                if isinstance(node,ast.Call):
                    sink=qualify(node.func,m)
                    if sink in DRIVERS:
                        for k in node.keywords:
                            if k.arg not in CREDENTIALS:continue
                            v=evaluate(k.value,module,local)
                            if v and 3<=len(v)<=4096:
                                values.add(v);evidence.append({'file':m['path'],'line':node.lineno,'sink':sink,'argument':k.arg,'value_sha256':hashlib.sha256(v.encode()).hexdigest()})
                for child in ast.iter_child_nodes(node):walk(child)
            walk(scope)
    return {'values':sorted(values),'evidence':evidence,'skipped_invalid_python':skipped,
            'limitations':'selected named driver arguments, constants/aliases/simple local imports only; no full control flow or interprocedural analysis'}

if __name__=='__main__':
    try:print(json.dumps(discover(json.load(sys.stdin)['repo'])))
    except Exception:sys.exit(2)
