import ast, pathlib, unittest, copy
P=pathlib.Path(__file__).resolve().parent
class Pins(unittest.TestCase):
 def test_each_variant_exact_worker_and_embedded_scripts(self):
  for name in ['vgw-continuous-traffic-v8.py','tgw-continuous-v6.py']:
   tree=ast.parse((P/name).read_text());f=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate_worker_pin');ns={};exec(compile(ast.Module(body=[f],type_ignores=[]),name,'exec'),ns)
   pin={'root_reviewed':True,'gateway_id':'35a889a1a6b7e521084715f51a2fb6f8537b581647f8c7ebfa9b61e258df6605','node_sha256':'296065d03c4e1f6b69f27708ab9a33d09f77004817bb5f57c10d622c3f30e75c','namespace':'net:[4026532946]','host_pid':3115397,'started_at':'2026-10-08T14:46:54.478240323Z','source_manifest_sha256':'4674c202643ef54f7239bd1c54af7fd78248b446e743da61b3ef229efc91ec1e','build_receipt_sha256':'6ac029070ad8ccf9174b9744c7291c1834798a5bebadb114b90c444cc30ab6e6','image':'sha256:868b425d65ef30b6f0c221c834e8925079d658281e89380ead59a929021c50a2','cert_sha256':'eef07a8865a43de26d8dafbc26e26327cf9d850adc3fd65112baf776d452ea8d'}
   ns['validate_worker_pin'](pin)
   for field in pin:
    q=copy.deepcopy(pin);q[field]=False if field=='root_reviewed' else 0 if field=='host_pid' else 'foreign'
    with self.subTest(name=name,field=field),self.assertRaises(AssertionError):ns['validate_worker_pin'](q)
   for n in ast.walk(tree):
    if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id in ['identity_code','client_code','fixture_code'] for x in n.targets):
     if isinstance(n.value,ast.Constant):compile(n.value.value,'embedded','exec')
     elif isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute)and isinstance(n.value.func.value,ast.Constant):compile(n.value.func.value.value.replace('RUN_LITERAL',repr('0'*32)),'embedded','exec')
   # Lifetime loops never repurpose the SSH key variable.
   self.assertFalse(any(isinstance(n,(ast.For,ast.comprehension)) and isinstance(n.target,ast.Name)and n.target.id=='key'for n in ast.walk(tree)))
unittest.main()
