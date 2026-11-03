"""Conservative CSV/TOML views. No repository code execution or dependency download."""
import csv
import io
import json
import re
import sys


def project(data):
    found=[]
    def hide(v):
        if v is not None and v!='':found.append(str(v))
        return '[REDACTED]'
    if data['format']=='csv':
        # No implicit header declassification: an untrusted first row can itself
        # hold secrets. Cell count/row count remain visible structural metadata.
        rows=list(csv.reader(io.StringIO(data['text']),strict=True))
        out=io.StringIO();writer=csv.writer(out,lineterminator='\n')
        for row in rows:writer.writerow([hide(v) for v in row])
        return {'text':out.getvalue(),'discovered':found}
    if data['format']=='toml':
        import tomllib  # Python 3.11+; older environments fail closed in Node.
        obj=tomllib.loads(data['text']);schema=data.get('schema',{})
        def walk(v,parts=()):
            if isinstance(v,dict):return {k:walk(x,(*parts,k)) for k,x in v.items()}
            if isinstance(v,list):return [walk(x,(*parts,str(i))) for i,x in enumerate(v)]
            pointer='/'+'/'.join(str(x).replace('~','~0').replace('/','~1') for x in parts) if parts else ''
            if data.get('scoped'):
                rule=schema.get(pointer,schema.get(parts[0],{}) if len(parts)==1 and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',str(parts[0])) else {})
            else:rule=schema.get('.'.join(parts),schema.get(parts[-1] if parts else '',{}))
            if rule.get('type')=='int' and type(v) is int and rule.get('min',-float('inf'))<=v<=rule.get('max',float('inf')):return v
            return hide(v)
        return {'text':json.dumps(walk(obj),ensure_ascii=False,indent=2)+'\n','discovered':found}
    raise ValueError('unsupported format')

if __name__=='__main__':
    try:print(json.dumps(project(json.load(sys.stdin))))
    except Exception:sys.exit(2)
