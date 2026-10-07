"""Bounded hashed business-data lineage; labels come from policy/schema, not claims."""
import base64,hashlib,json,re,sqlite3
from collections import OrderedDict
from pathlib import Path
from urllib.parse import quote,unquote
from knowledge_graph import Graph,strings

SENSITIVE_FIELDS=re.compile(r'(?:^|_)(password|passwd|secret|api_key|private_key|passport|ssn|social_security|diagnosis|medical_record)(?:$|_)',re.I)
DESTINATION=re.compile(r'(?:^|_)(to|recipient|receiver|url|endpoint|destination|webhook)(?:$|_)',re.I)


def sha(text):return hashlib.sha256(text.encode()).hexdigest()


def representations(text):
    # Long exact values and overlapping fragments support bounded partial leakage.
    chunks=[text]+[text[i:i+64] for i in range(0,min(len(text),4096),32) if len(text[i:i+64])>=32]
    for piece in chunks:
        if len(piece)<12:continue
        yield piece,'identity'
        yield base64.b64encode(piece.encode()).decode(),'base64'
        yield piece.encode().hex(),'hex'
        yield quote(piece,safe=''),'url'


class BusinessFlow:
    def __init__(self,policy=None,path=None,max_sources=128):
        self.policy=policy or {'version':1,'sources':[],'release':[]}
        if type(self.policy.get('version')) is not int or self.policy['version']!=1 or not all(isinstance(self.policy.get(k,[]),list) for k in ['sources','release']):raise ValueError('invalid business policy')
        for kind in ['sources','release']:
            for rule in self.policy.get(kind,[]):
                required=['server','tool','label']+(['principal'] if kind=='release' else [])
                if not isinstance(rule,dict) or any(not isinstance(rule.get(k),str) or not rule[k] for k in required):raise ValueError('invalid business rule')
                values=rule.get('fields' if kind=='sources' else 'destinations')
                if not isinstance(values,list) or not values or any(not isinstance(v,str) or not v for v in values):raise ValueError('invalid business rule values')
        self.namespace=sha(json.dumps({'policy':self.policy,'algorithm':1,'max_sources':max_sources},sort_keys=True))
        self.sources=OrderedDict();self.forms={};self.max_sources=max_sources;self.saturated=False;self.sequence=0;self.restored=False
        self.db=None;self.stats={'observed':0,'sources':0,'findings':0,'writes':0}
        if path:
            Path(path).parent.mkdir(parents=True,exist_ok=True)
            self.db=sqlite3.connect(path,check_same_thread=False);self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('CREATE TABLE IF NOT EXISTS business(namespace TEXT PRIMARY KEY,payload TEXT NOT NULL)')
            rows=self.db.execute('SELECT namespace,payload FROM business').fetchall()
            if any(n!=self.namespace for n,v in rows):self.db.close();raise ValueError('business provenance namespace mismatch')
            if rows:
                state=json.loads(rows[0][1]);self.sources=OrderedDict(state['sources']);self.forms=state['forms'];self.sequence=state['sequence'];self.saturated=state['saturated'];self.restored=True
                if len(self.sources)>max_sources or len(self.forms)>8192:raise ValueError('restored business ledger exceeds bounds')
                self.stats['sources']=len(self.sources)

    def close(self):
        if self.db:self.db.close();self.db=None

    def save(self):
        if self.db:
            with self.db:self.db.execute('INSERT OR REPLACE INTO business VALUES(?,?)',(self.namespace,json.dumps({'sources':list(self.sources.items()),'forms':self.forms,'sequence':self.sequence,'saturated':self.saturated})))
            self.stats['writes']+=1

    def labeled(self,call,result):
        # Bounded JSON traversal and decode; no external classification field grants.
        stack=[result];count=0
        for text in strings(result):
            if text.lstrip().startswith(('{','[')) and len(text)<32768:
                try:stack.append(json.loads(text))
                except (ValueError,RecursionError):pass
        explicit=[r for r in self.policy.get('sources',[]) if r.get('server')==call.server and r.get('tool')==call.tool]
        while stack:
            node=stack.pop();count+=1
            if count>4096:raise ValueError('business traversal exceeded')
            if isinstance(node,dict):
                for key,value in node.items():
                    labels={r['label'] for r in explicit if key in r.get('fields',[])}
                    if SENSITIVE_FIELDS.search(str(key)):labels.add('sensitive-schema-field')
                    if labels:
                        for text in strings(value):
                            if len(text)>4096:raise ValueError('sensitive value exceeds inspection budget')
                            if 12<=len(text):yield text,sorted(labels),str(key)
                    stack.append(value)
            elif isinstance(node,list):stack.extend(node)

    def observe(self,principal,session,call,result,ok=True):
        if not ok:return
        self.sequence+=1;self.stats['observed']+=1;changed=False
        try:
            for text,labels,field in self.labeled(call,result):
                key=sha(text)
                if key not in self.sources:
                    if len(self.sources)>=self.max_sources:self.saturated=True;changed=True;break
                    self.sources[key]={'principal':principal,'session':session,'server':call.server,'tool':call.tool,'field':field,'labels':labels,'sequence':self.sequence,'exposed_to':[principal]};changed=True
                    for raw,form in representations(text):
                        if len(self.forms)>=8192:self.saturated=True;break
                        self.forms.setdefault(sha(raw),[]).append([key,form,len(raw)])
                else:
                    # Labels only accumulate. A later lower-sensitivity source
                    # cannot erase an earlier deployment-owned classification.
                    merged=sorted(set(self.sources[key]['labels'])|set(labels))
                    if merged!=self.sources[key]['labels']:
                        self.sources[key]['labels']=merged;changed=True
            # A successful return carrying known bytes proves exposure to the reader;
            # it does not imply consent to release them to a destination.
            for key,form in self.hits(result):
                source=self.sources[key]
                if principal not in source['exposed_to']:
                    if len(source['exposed_to'])>=256:self.saturated=True
                    else:
                        source['exposed_to'].append(principal)
                        source.setdefault('read_hops',[]).append({'principal':principal,'session':session,'server':call.server,'tool':call.tool,'sequence':self.sequence,'transform':form})
                    changed=True
            self.stats['sources']=len(self.sources)
        except ValueError:
            self.saturated=True;changed=True
            raise
        finally:
            if changed:self.save()

    def hits(self,value):
        if not self.forms:return []
        found={}
        for text in strings(value):
            candidates=[(text,'identity'),(unquote(text),'url-decode')]
            for token in re.findall(r'[A-Za-z0-9_+/%=.-]{12,16384}',text):
                candidates.append((token,'identity'))
                if len(token)%4==0:
                    try:candidates.append((base64.b64decode(token,validate=True).decode(),'base64-decode'))
                    except (ValueError,UnicodeError):pass
                if len(token)%2==0 and re.fullmatch(r'[0-9a-fA-F]+',token):
                    try:candidates.append((bytes.fromhex(token).decode(),'hex-decode'))
                    except (ValueError,UnicodeError):pass
            for raw,transform in candidates[:256]:
                hashes=[sha(raw)]
                # Only fixed fragment sizes are scanned; avoid all source lengths.
                if len(raw)<=8192:
                    for size in [32,64]:
                        if len(raw)>size:hashes.extend(sha(raw[i:i+size]) for i in range(len(raw)-size+1))
                for fingerprint in hashes:
                    for key,form,size in self.forms.get(fingerprint,[]):found[key]=transform if transform!='identity' else form
        return list(found.items())

    def check(self,principal,session,call):
        if not (set(call.caps)&{'net','exec'}):return []
        if self.saturated:return [{'rule_id':'r10-business-budget','summary':'business provenance incomplete; egress requires review','graph':{'nodes':[],'edges':[]}}]
        destinations={str(value) for key,value in call.arguments.items() if DESTINATION.search(key) and isinstance(value,str)}
        findings=[]
        for key,transform in self.hits(call.arguments):
            source=self.sources[key]
            if principal not in source['exposed_to']:continue
            permitted=destinations and all(any(r.get('principal')==principal and r.get('server')==call.server and r.get('tool')==call.tool and label==r.get('label') and destinations<=set(r.get('destinations',[])) for r in self.policy.get('release',[])) for label in source['labels'])
            if permitted:continue
            graph=Graph();graph.node('origin','Call',**{k:v for k,v in source.items() if k not in {'read_hops','exposed_to'}})
            graph.node('data','BusinessData',fingerprint=key,labels=source['labels'])
            graph.node('representation','Representation',transform=transform)
            graph.node('sink','Call',principal=principal,session=session,server=call.server,tool=call.tool)
            graph.edge('origin','returns','data')
            previous='data'
            for index,hop in enumerate(source.get('read_hops',[])):
                if hop['principal']!=principal:continue
                node=f'read-{index}';graph.node(node,'Call',**hop)
                graph.edge(previous,'exposed_by',''+node);previous=node
            graph.edge(previous,'represented_as','representation');graph.edge('representation','used_by','sink')
            findings.append({'rule_id':'r10-business-flow','summary':'observed labeled business data has no deployment release permission',
                'graph':graph.json(),'path':graph.edges,'source_fingerprint':key,'transform':transform,'labels':source['labels'],'policy_sha256':self.namespace})
        self.stats['findings']+=len(findings);return findings
