import copy,importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('phase2',pathlib.Path(__file__).with_name('customer-static-central-phase2-v2.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TagSetProof(unittest.TestCase):
 def fixture(self):
  tags=[{'Key':'TunnexLab','Value':m.OWNER}]
  p={'target_id':'i-owned','primary_eni_id':'eni-primary','primary_mac':'02:00:00:00:00:01','secondary_eni_id':'eni-secondary','secondary_mac':'02:00:00:00:00:02','secondary_subnet_id':'subnet-secondary','vpc_id':'vpc-owned','security_group_id':'sg-owned'}
  primary={'Attachment':{'DeviceIndex':0},'NetworkInterfaceId':p['primary_eni_id'],'PrivateIpAddress':'10.87.1.10','MacAddress':p['primary_mac']}
  target={'InstanceId':p['target_id'],'State':{'Name':'running'},'InstanceType':'t3.micro','Tags':tags,'Placement':{'AvailabilityZone':'eu-central-1a'},'NetworkInterfaces':[primary],'VpcId':p['vpc_id']}
  eni={'NetworkInterfaceId':p['secondary_eni_id'],'TagSet':tags,'Status':'available','Attachment':None,'PrivateIpAddress':'10.87.2.10','PrivateIpAddresses':[{'PrivateIpAddress':'10.87.2.10'}],'MacAddress':p['secondary_mac'],'SubnetId':p['secondary_subnet_id'],'VpcId':p['vpc_id'],'Groups':[{'GroupId':p['security_group_id']}]}
  subnet={'SubnetId':p['secondary_subnet_id'],'Tags':tags,'CidrBlock':'10.87.2.0/24','AvailabilityZone':'eu-central-1a','VpcId':p['vpc_id']}
  return target,eni,subnet,p
 def test_actual_eni_tagset_shape(self):
  t,e,s,p=self.fixture();self.assertEqual(m.validate(t,e,s,p),t['NetworkInterfaces'][0])
 def test_tags_only_eni_refused(self):
  t,e,s,p=self.fixture();e['Tags']=e.pop('TagSet')
  with self.assertRaises(AssertionError):m.validate(t,e,s,p)
 def test_owner_mac_attachment_index_boundaries(self):
  for change in [lambda t,e,s:e.update(TagSet=[{'Key':'TunnexLab','Value':'foreign'}]),lambda t,e,s:e.update(MacAddress='02:00:00:00:00:99'),lambda t,e,s:e.update(Attachment={'DeviceIndex':0}),lambda t,e,s:t['NetworkInterfaces'][0]['Attachment'].update(DeviceIndex=1),lambda t,e,s:e.update(TagSet={'TunnexLab':m.OWNER}),lambda t,e,s:s.update(Tags=[])]:
   t,e,s,p=self.fixture();change(t,e,s)
   with self.assertRaises(AssertionError):m.validate(t,e,s,p)
if __name__=='__main__':unittest.main()
