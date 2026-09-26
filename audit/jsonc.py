import json, re
def loads(t):
    out=[]; i=0; n=len(t); ins=False
    while i<n:
        c=t[i]
        if ins:
            out.append(c)
            if c==chr(92): out.append(t[i+1]); i+=2; continue
            if c=='"': ins=False
            i+=1; continue
        if c=='"': ins=True; out.append(c); i+=1; continue
        if t.startswith('//',i):
            j=t.find('\n',i); i=n if j<0 else j; continue
        if t.startswith('/*',i):
            j=t.find('*/',i); i=n if j<0 else j+2; continue
        out.append(c); i+=1
    s=re.sub(r',(\s*[}\]])',r'\1',''.join(out))
    return json.loads(s)
