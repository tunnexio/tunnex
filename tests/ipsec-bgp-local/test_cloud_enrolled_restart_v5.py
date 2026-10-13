import ast,json,pathlib,unittest
source=pathlib.Path(__file__).with_name('cloud-enrolled-restart-v5.py')
names={'OLD','NS','IMAGE','NODE','DELIVERY','OBSERVER','CLI','GATE','NAME','STAGING','WRAPPER','D','NEW_NODE','NEW_SOURCE','OLD_BIN_DIR','NEW_BIN_DIR','NEW_RECEIPT_SHA'}
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
 def links(self,index=2):return [{'ifname':'eth0','ifindex':index,'operstate':'UP','flags':['UP','LOWER_UP'],'link_type':'ether','linkinfo':{'info_kind':'veth'},'address':'02:42:ac:1e:58:02','mtu':1500}]
 def addresses(self):return [{'ifname':'eth0','addr_info':[{'family':'inet','local':'172.30.88.2','prefixlen':24,'scope':'global','broadcast':'172.30.88.255','label':'eth0'}]}]
 def test_fresh_index_bound_without_old_epoch_adoption(self):
  proof=m['link_proof'](self.links(4),self.addresses(),self.links(2),self.addresses());self.assertEqual(proof['current_ifindex'],4);self.assertEqual(proof['old_ifindex'],2)
  for field,value in [('operstate','DOWN'),('ifindex',0),('address','foreign'),('flags',['UP']),('linkinfo',{'info_kind':'xfrm'})]:
   bad=self.links(4);bad[0][field]=value
   with self.assertRaises(AssertionError):m['link_proof'](bad,self.addresses(),self.links(),self.addresses())
  bad=self.addresses();bad[0]['addr_info'][0]['local']='13.63.169.255'
  with self.assertRaises(AssertionError):m['link_proof'](self.links(),bad,self.links(),self.addresses())
 def test_outside_source_route_proof(self):
  route={'dst':'13.50.7.159','gateway':'172.30.88.1','dev':'eth0','prefsrc':'172.30.88.2','flags':[]};self.assertEqual(m['routeget_proof']([route],'13.50.7.159'),route)
  for change in [{'dev':'txForeign'},{'gateway':'172.30.88.99'},{'prefsrc':'13.63.169.255'},{'flags':['linkdown']},{'dst':'13.50.7.141'},{'table':100}]:
   with self.assertRaises(AssertionError):m['routeget_proof']([dict(route,**change)],'13.50.7.159')
  bad=dict(route);bad.pop('prefsrc')
  with self.assertRaises(AssertionError):m['routeget_proof']([bad],'13.50.7.159')
 def test_abort_gate_exact_created_inode_and_content_only(self):
  actual={'device':1,'inode':2,'uid':0,'mode':0o600};record={'old':m['OLD'],'journal_sha256':'fixed','identity':actual.copy()}
  self.assertTrue(m['gate_proof'](actual,record,m['GATE'],'fixed'))
  for change in [{'inode':3},{'device':2},{'uid':501},{'mode':0o644}]:
   with self.assertRaises(AssertionError):m['gate_proof'](dict(actual,**change),record,m['GATE'],'fixed')
  with self.assertRaises(AssertionError):m['gate_proof'](actual,record,b'foreign','fixed')
  with self.assertRaises(AssertionError):m['gate_proof'](actual,dict(record,old='foreign'),m['GATE'],'fixed')
  with self.assertRaises(AssertionError):m['gate_proof'](actual,record,m['GATE'],'changed')
 def test_abort_only_same_paused_pre_kill_identity(self):
  b={'Id':m['OLD'],'Image':m['IMAGE'],'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{'Networks':{}},'State':{'Running':True,'Pid':123,'StartedAt':'exact'}};m['base']={'journal_sha256':'fixed'}
  self.assertTrue(m['abort_allowed'](b,b,'fixed',{'cert':'same'},{'cert':'same'},False,False))
  for kill,proof in [(True,False),(False,True),(True,True)]:
   with self.assertRaises(AssertionError):m['abort_allowed'](b,b,'fixed',{}, {},kill,proof)
  import copy
  for change in [{'Pid':124},{'StartedAt':'other'},{'Running':False}]:
   g=copy.deepcopy(b);g['State'].update(change)
   with self.assertRaises(AssertionError):m['abort_allowed'](g,b,'fixed',{}, {},False,False)
  with self.assertRaises(AssertionError):m['abort_allowed'](b,b,'changed',{}, {},False,False)
  with self.assertRaises(AssertionError):m['abort_allowed'](b,b,'fixed',{'cert':'changed'},{'cert':'same'},False,False)
 def upgrade_layout(self):
  return {'HostConfig':{'Binds':None,'Mounts':[{'Type':'bind','Source':m['OLD_BIN_DIR'],'Target':'/binaries','ReadOnly':True},{'Type':'volume','Source':'original-state','Target':'/state'}],'Memory':100,'SecurityOpt':['no-new-privileges:true']},'Mounts':[{'Type':'bind','Source':m['OLD_BIN_DIR'],'Destination':'/binaries','RW':False,'Propagation':'rprivate'},{'Type':'volume','Name':'original-state','Destination':'/state','RW':True}]}
 def test_engine_oom_default_normalization_new_only(self):
  import copy
  old=self.upgrade_layout();old['HostConfig']['OomKillDisable']=None;before=copy.deepcopy(old)
  created=m['creation_host_config'](old);self.assertIs(created['OomKillDisable'],False);self.assertEqual(old,before)
  expected=m['replacement_host_config'](old);expected['OomKillDisable']=False;self.assertEqual(created,expected)
  for value in [True,False]:
   old['HostConfig']['OomKillDisable']=value;self.assertIs(m['creation_host_config'](old)['OomKillDisable'],value)
 def test_only_new_binary_mount_source_changes(self):
  import copy
  old=self.upgrade_layout();before=copy.deepcopy(old);changed=m['replacement_host_config'](old);mounts=m['replacement_mounts'](old)
  self.assertEqual(old,before);expected=copy.deepcopy(old['HostConfig']);expected['Mounts'][0]['Source']=m['NEW_BIN_DIR'];self.assertEqual(changed,expected)
  expected_mounts=copy.deepcopy(old['Mounts']);expected_mounts[0]['Source']=m['NEW_BIN_DIR'];self.assertEqual(mounts,expected_mounts)
  for field,value in [('Source','foreign'),('ReadOnly',False),('Type','volume')]:
   bad=copy.deepcopy(old);bad['HostConfig']['Mounts'][0][field]=value
   with self.assertRaises(AssertionError):m['replacement_host_config'](bad)
  bad=copy.deepcopy(old);bad['Mounts'][0]['RW']=True
  with self.assertRaises(AssertionError):m['replacement_mounts'](bad)
 def test_complete_binary_inventory_exact_hash_mode_uid_only(self):
  old={'tunnex-node':{'sha256':m['NODE'],'mode':0o700,'uid':0},'tunnex-api':{'sha256':'originalAPI','mode':0o700,'uid':0}};new={'tunnex-node':{'sha256':m['NEW_NODE'],'mode':0o700,'uid':0},'tunnex-api':old['tunnex-api'].copy()}
  self.assertTrue(m['upgrade_inventory'](old,new))
  with self.assertRaises(AssertionError):m['upgrade_inventory'](old,{'tunnex-node':new['tunnex-node']})
  import copy
  for field,value in [('sha256','foreign'),('mode',0o755),('uid',501)]:
   bad=copy.deepcopy(new);bad['tunnex-api'][field]=value
   with self.assertRaises(AssertionError):m['upgrade_inventory'](old,bad)
  for field,value in [('sha256',m['NODE']),('mode',0o777),('uid',501)]:
   bad=copy.deepcopy(new);bad['tunnex-node'][field]=value
   with self.assertRaises(AssertionError):m['upgrade_inventory'](old,bad)
  bad=copy.deepcopy(new);bad['unknown']='extra'
  with self.assertRaises(AssertionError):m['upgrade_inventory'](old,bad)
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
