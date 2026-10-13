import ast,json,pathlib,unittest
source=pathlib.Path(__file__).with_name('cloud-enrolled-restart-v2.py')
names={'OLD','NS','IMAGE','NODE','DELIVERY','OBSERVER','CLI','GATE','NAME','STAGING','WRAPPER','D'}
tree=ast.parse(source.read_text());body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.ClassDef))or isinstance(n,ast.Assign)and all(isinstance(t,ast.Name)and t.id in names for t in n.targets)]
m={};exec(compile(ast.Module(body=body,type_ignores=[]),str(source),'exec'),m)
class CloudRestartBoundaries(unittest.TestCase):
 def entry(self):return {'DeliveryID':m['DELIVERY'],'Phase':'applied','ContractVersion':3,'BGPProcess':{'Stage':'ready'},'BGPRoutes':{'Stage':'completed'}}
 def test_single_active_preserves_retained_history(self):
  e=self.entry();raw=json.dumps({'Payload':{'Entries':[{'Phase':'retained_refusal'},e]}}).encode();self.assertEqual(m['active'](raw),e)
  for change in [{'DeliveryID':'foreign'},{'Phase':'cleanup_pending'},{'ContractVersion':2},{'BGPProcess':{'Stage':'cleaned'}},{'BGPRoutes':{'Stage':'pending'}}]:
   bad=dict(e,**change)
   with self.assertRaises(AssertionError):m['active'](json.dumps({'Payload':{'Entries':[bad]}}).encode())
  with self.assertRaises(AssertionError):m['active'](json.dumps({'Payload':{'Entries':[e,e]}}).encode())
 def test_actual_shell_shape_preserved(self):
  actual={'Config':{'Entrypoint':['/bin/sh'],'Cmd':['-ec','exec /binaries/tunnex-node']}}
  self.assertEqual(m['cloud_command'](actual),'exec /binaries/tunnex-node')
  for bad in [{'Entrypoint':['/bin/sh','-ec'],'Cmd':['exec node']},{'Entrypoint':['/bin/sh'],'Cmd':['-c','exec node']},{'Entrypoint':['/bin/sh'],'Cmd':['-ec',m['WRAPPER']+'exec node']}]:
   with self.assertRaises(AssertionError):m['cloud_command']({'Config':bad})
 def test_all_original_udp_tcp_publications_required(self):
  ports={k:[{'HostIp':'0.0.0.0','HostPort':v}]for k,v in [('500/udp','500'),('4500/udp','4500'),('9091/tcp','19393')]}
  actual={'HostConfig':{'PortBindings':ports}};self.assertEqual(m['publication_contract'](actual),ports)
  for key in ports:
   bad=dict(ports);bad.pop(key)
   with self.assertRaises(AssertionError):m['publication_contract']({'HostConfig':{'PortBindings':bad}})
  bad=dict(ports);bad['4500/udp']=[{'HostIp':'0.0.0.0','HostPort':'24500'}]
  with self.assertRaises(AssertionError):m['publication_contract']({'HostConfig':{'PortBindings':bad}})
 def route(self,dst='10.84.2.0/24'):return {'dst':dst,'gateway':'172.30.88.1','dev':'eth0','protocol':'static','flags':[]}
 def read(self,routes):
  m['execout']=lambda *args:json.dumps(routes).encode();return m['lan_routes']('fixture')
 def test_exact_manual_tgw_lan_replay(self):
  routes=[self.route(),dict(self.route('10.84.3.0/24'),metric=51084),{'dst':'10.86.0.0/16','dev':'txForeign','protocol':242}]
  got,allrows=self.read(routes);self.assertEqual(len(got),2);self.assertEqual(allrows,routes)
 def test_foreign_or_ambiguous_lan_refused(self):
  for change in [{'gateway':'172.30.88.99'},{'dev':'txForeign'},{'protocol':242},{'flags':['linkdown']},{'prefsrc':'13.63.169.255'},{'table':100},{'unsupported':1}]:
   with self.assertRaises(AssertionError):self.read([dict(self.route(),**change),dict(self.route('10.84.3.0/24'),metric=51084)])
  with self.assertRaises(AssertionError):self.read([self.route(),self.route(),dict(self.route('10.84.3.0/24'),metric=51084)])
  with self.assertRaises(AssertionError):self.read([self.route(),dict(self.route('10.84.3.0/24'),metric=51085)])
if __name__=='__main__':unittest.main()
