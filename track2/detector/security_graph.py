"""R8: deployment-bound joint evidence, durable bounded propagation and intervention.

This module never loads labels or trajectories. Static input is an administrator
mounted inventory. Persisted representation indices are hashes, not raw secrets.
SQLite protects atomicity, not confidentiality or authenticity against an actor
who can write this private state directory. Single worker per state file.
"""
from collections import OrderedDict
import hashlib
import json
import sqlite3
from pathlib import Path
import time
from knowledge_graph import KnowledgeGuard,Graph,candidates
from intervention import ResultPolicies,minimum_intervention

COMPONENTS={'joint','multi_hop','persistence','planner','isolation'}


class SecurityGraph(KnowledgeGuard):
    def __init__(self,inventory=None,result_policy=None,state_path=None,components=None,
                 lease_seconds=86400,max_hops=4,clock=time.time,**kwargs):
        super().__init__(**kwargs)
        self.features=COMPONENTS if components is None else set(components)
        if not self.features<=COMPONENTS or not 1<=max_hops<=4 or lease_seconds<=0:
            raise ValueError('Invalid R8 configuration')
        self.clock,self.max_hops,self.lease_seconds=clock,max_hops,lease_seconds
        self.policy=ResultPolicies(result_policy)
        self.inventory=inventory
        self.tools={a['name']:a.get('attributes',{}) for a in (inventory or {}).get('asset_graph',{}).get('assets',[]) if a.get('kind')=='tool'}
        self.namespace=hashlib.sha256(json.dumps({'inventory':inventory,'policy':self.policy.document,
            'max_hops':max_hops,'max_sources':self.max_sources,'features':sorted(self.features),'lease_seconds':lease_seconds},sort_keys=True).encode()).hexdigest()
        self.routes={}; self.db=None; self.restored=False; self.expired=False
        self.expires_at=self.clock()+lease_seconds
        self.stats.update(joint_checked=0,joint_findings=0,planner_runs=0,persist_writes=0,
                          isolated=0,result_denied=0)
        if state_path and 'persistence' in self.features:
            path=Path(state_path); path.parent.mkdir(parents=True,exist_ok=True)
            self.db=sqlite3.connect(path,timeout=2,check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('CREATE TABLE IF NOT EXISTS state(namespace TEXT PRIMARY KEY,payload TEXT NOT NULL)')
            # A single file must never silently accumulate or reuse stale versions.
            rows=self.db.execute('SELECT namespace,payload FROM state').fetchall()
            if rows and any(row[0]!=self.namespace for row in rows):
                self.saturated=True
                self.close()
                raise ValueError('Persistent namespace mismatch: use a new private state file')
            if rows:
                try:
                    self._restore(json.loads(rows[0][1])); self.restored=True
                    self._expire()
                except Exception:
                    self.close(); raise

    def close(self):
        if self.db is not None: self.db.close(); self.db=None

    def _expire(self):
        if not self.expired and self.clock()>=self.expires_at:
            # Expiry is uncertainty, not permission to send previously labelled data.
            had_sources=bool(self.sources or self.artifacts)
            self.sources.clear();self.forms.clear();self.exposures.clear();self.artifacts.clear();self.routes.clear()
            self.expired=True;self.saturated |= had_sources
            self._save()

    def _payload(self):
        return {'sources':[[list(k),v] for k,v in self.sources.items()],
            'forms':{k:[[list(key),form] for key,form in values] for k,values in self.forms.items()},
            'exposures':{p:[list(k) for k in keys] for p,keys in self.exposures.items()},
            'artifacts':list(self.artifacts.items()),
            'routes':[[p,list(k),route] for (p,k),route in self.routes.items()],
            'sequence':self.sequence,'saturated':self.saturated,'stats':self.stats,
            'expires_at':self.expires_at,'expired':self.expired}

    def _restore(self,value):
        if len(value['sources'])>self.max_sources or len(value['artifacts'])>self.max_sources or len(value['routes'])>self.max_sources**2*2:
            raise ValueError('Persistent state budget exceeded')
        self.sources=OrderedDict((tuple(k),v) for k,v in value['sources'])
        self.forms={k:[(tuple(key),form) for key,form in values] for k,values in value['forms'].items()}
        self.exposures={p:{tuple(k) for k in keys} for p,keys in value['exposures'].items()}
        self.artifacts=OrderedDict(value['artifacts'])
        self.routes={(p,tuple(k)):route for p,k,route in value['routes']}
        self.sequence=value['sequence'];self.saturated=value['saturated'];self.stats.update(value['stats'])
        self.expires_at=value['expires_at'];self.expired=value['expired']

    def _save(self):
        if self.db is not None:
            self.stats['persist_writes']+=1
            with self.db:
                self.db.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(self.namespace,json.dumps(self._payload())))

    def _matches(self,arguments,principal):
        if not self.forms: return []
        exposed=self.exposures.get(principal,set())
        return [(key,form) for text in candidates(arguments)
            for key,form in self.forms.get(hashlib.sha256(text.encode()).hexdigest(),[]) if key in exposed]

    def _joint(self,call):
        if 'joint' not in self.features or self.inventory is None: return []
        self.stats['joint_checked']+=1
        name=call.server+'.'+call.tool
        attrs=self.tools.get(name)
        reason=None
        if attrs is None: reason='runtime tool absent from deployment inventory'
        elif attrs.get('declared_in_tools_list') is False and set(attrs.get('code_caps',[])) & {'net','exec'}:
            reason='runtime invokes a source-registered hidden high-risk tool'
        if reason is None: return []
        graph=Graph()
        graph.node('call','Call',server=call.server,tool=call.tool)
        graph.node('tool','Tool',name=name)
        graph.node('inventory','StaticInventory',namespace=self.namespace,registered=attrs is not None)
        graph.edge('call','invokes','tool');graph.edge('tool','checked_against','inventory')
        if attrs is not None:
            graph.node('source','SourceRegistration',**attrs.get('source_registration',{}))
            graph.node('capability','Capability',names=attrs.get('code_caps',[]),declared=False)
            graph.edge('tool','registered_at','source');graph.edge('source','implements','capability')
        path=graph.path('call','capability' if attrs is not None else 'inventory',
                        {'invokes','checked_against','registered_at','implements'})
        self.stats['joint_findings']+=1
        return [{'rule_id':'r8-joint-asset','summary':reason,'graph':graph.json(),'path':path}]

    def _plan(self,findings):
        if not findings: return findings
        paths=[{'id':str(i),'rule':f['rule_id'],'path':f.get('path',[])} for i,f in enumerate(findings)]
        candidates_=[{'id':'deny-current-call','cost':1,'covers':[p['id'] for p in paths]},
                     {'id':'abort-task','cost':10,'covers':[p['id'] for p in paths]}]
        plan=minimum_intervention(paths,candidates_ if 'planner' in self.features else candidates_[1:])
        self.stats['planner_runs']+=1
        for f in findings: f['intervention']=plan
        return findings

    def check(self,principal,session,call):
        self._expire()
        joint=self._joint(call)
        inferred=super().check(principal,session,call)
        for finding in inferred:
            if finding['rule_id']=='kg-sensitive-flow': self._expand_path(principal,finding)
        return self._plan(joint+inferred)

    def _expand_path(self,principal,finding):
        graph=finding['graph']
        source=next(n for n in graph['nodes'] if n['id']=='source')
        key=(source['principal'],source['fingerprint'])
        route=self.routes.get((principal,key),[])
        if not route: return
        proof=Graph()
        proof.nodes={n['id']:n for n in graph['nodes']}
        proof.edges=[e for e in graph['edges'] if not (e['src']=='data' and e['dst']=='representation')]
        previous='data';prior_sequence=source['sequence']
        for index,hop in enumerate(route):
            if not prior_sequence<hop['write_sequence']<hop['read_sequence']<self.sequence:
                raise ValueError('Invalid persistent temporal provenance')
            writer=proof.node(f'w{index}','Call',principal=hop['writer'],session=hop['write_session'],sequence=hop['write_sequence'])
            artifact=proof.node(f'a{index}','Resource',fingerprint=hop['resource'],scope='shared')
            reader=proof.node(f'r{index}','Call',principal=hop['reader'],session=hop['read_session'],sequence=hop['read_sequence'])
            derived=proof.node(f'd{index}','Data',fingerprint=source['fingerprint'])
            proof.edge(previous,'written_by',writer);proof.edge(writer,'writes',artifact)
            proof.edge(artifact,'read_by',reader);proof.edge(reader,'returns',derived)
            previous=derived;prior_sequence=hop['read_sequence']
        proof.edge(previous,'encoded_as','representation')
        path=proof.path('source','effect',{'returns','written_by','writes','read_by',
            'encoded_as','used_as_argument','invokes','has_capability'},max_depth=24)
        if path is None: raise ValueError('Missing multi-hop path')
        finding.update(graph=proof.json(),path=path,shared_resource_hops=len(route))

    def observe(self,principal,session,call,result,ok=True):
        try:
            return self._observe(principal,session,call,result,ok)
        except ValueError:
            # Inspection uncertainty must remain fail-closed after process restart.
            self.saturated=True
            self._save()
            raise

    def _observe(self,principal,session,call,result,ok=True):
        self._expire()
        if not ok or self.expired: return
        # R7 seeds sources into a temporary raw-form map. Keep only hashes after
        # the observation, so persistence cannot write the actual representations.
        saved,features=self.forms,self.components
        before=(len(self.sources),sum(map(len,self.exposures.values())),self.saturated)
        self.forms={};self.components=features-{'memory'}
        try: super().observe(principal,session,call,result,ok)
        finally:
            generated=self.forms;self.forms=saved;self.components=features
        changed=before!=(len(self.sources),sum(map(len,self.exposures.values())),self.saturated)
        for raw,values in generated.items():
            self.forms.setdefault(hashlib.sha256(raw.encode()).hexdigest(),[]).extend(values)
        resource=self._resource(call)
        if resource and 'memory' in self.components:
            matched=self._matches(call.arguments,principal)
            if 'fs_write' in call.caps and matched:
                if resource not in self.artifacts and len(self.artifacts)>=self.max_sources:
                    self.saturated=True;changed=True
                else:
                    entries=[]
                    for key in sorted({k for k,_ in matched}):
                        route=self.routes.get((principal,key),[])
                        if 'multi_hop' not in self.features and route:
                            continue
                        if len(route)>=self.max_hops:
                            self.saturated=True;changed=True;continue
                        entries.append({'key':list(key),'route':route,'writer':principal,
                            'write_session':session,'write_sequence':self.sequence})
                    if entries:
                        self.artifacts[resource]={'entries':entries};changed=True
            if set(call.caps)&{'fs_read','db_read','read_only'} and resource in self.artifacts:
                found={key for text in candidates(result) for key,_ in
                       self.forms.get(hashlib.sha256(text.encode()).hexdigest(),[])}
                for item in self.artifacts[resource]['entries']:
                    key=tuple(item['key'])
                    if key not in found: continue
                    self._expose(principal,key)
                    route=item['route']+[{'resource':resource,'writer':item['writer'],
                        'write_session':item['write_session'],'write_sequence':item['write_sequence'],
                        'reader':principal,'read_session':session,'read_sequence':self.sequence}]
                    self.routes[(principal,key)]=route;changed=True
        if changed: self._save()

    def project_result(self,call,body):
        if 'isolation' not in self.features: return body,None
        try: delivered,audit=self.policy.project(call,body,planner='planner' in self.features)
        except (ValueError,RecursionError): delivered,audit=self.policy._deny(body,'result traversal budget exceeded')
        if audit: self.stats['isolated' if audit['action']=='PROJECT' else 'result_denied']+=1
        return delivered,audit
