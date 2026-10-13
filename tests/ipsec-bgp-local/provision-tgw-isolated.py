#!/usr/bin/env python3
"""Authorized isolated TGW provisioner; run ONLY on designated bastion after review."""
import base64,datetime,hashlib,json,os,pathlib,secrets,subprocess,time,uuid,sys,fcntl
network_only=sys.argv[1:]==['--network-only'];assert not sys.argv[1:]or network_only
os.umask(0o077);OWNER='tunnex-bgp-tgw-20261008';ROOT=pathlib.Path('/home/ubuntu')/OWNER;ROOT.mkdir(mode=0o700,exist_ok=True);assert ROOT.stat().st_mode&0o777==0o700
# Existing operator key remains private on this host; never read or copy its contents.
assert subprocess.check_output(['curl','-fsS','--max-time','2','http://checkip.amazonaws.com']).decode().strip()=='16.170.207.192','Designated AWS CLI host required'
ledger=ROOT/'ledger.jsonl';sequence=0
if ledger.exists():sequence=sum(1 for _ in ledger.open())
def append(value):
 fd=os.open(ledger,os.O_RDWR|os.O_CREAT|os.O_APPEND,0o600)
 try:
  fcntl.flock(fd,fcntl.LOCK_EX);os.lseek(fd,0,os.SEEK_SET)
  with os.fdopen(os.dup(fd),'r')as stream:sequence=sum(1 for _ in stream)+1
  value={'sequence':sequence,'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'owner':OWNER,**value};os.write(fd,(json.dumps(value,sort_keys=True)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def save(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,(json.dumps(value,indent=2)+'\n').encode());os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def aws(action,request=None):
 args=['aws','ec2',action,'--region','eu-north-1','--output','json','--no-cli-pager','--cli-connect-timeout','10','--cli-read-timeout','30'];temp=None
 if request is not None:
  temp=ROOT/('request-'+uuid.uuid4().hex+'.json');save(temp,request);args+=['--cli-input-json','file://'+str(temp)]
 try:
  raw=subprocess.check_output(args,timeout=50);return json.loads(raw)if raw.strip()else{}
 finally:
  if temp is not None:temp.unlink()
def tags(kind,name):return [{'ResourceType':kind,'Tags':[{'Key':'TunnexLab','Value':OWNER},{'Key':'Name','Value':OWNER+'-'+name},{'Key':'ManagedBy','Value':'Tunnex-authorized-test'}]}]
def mutate(name,action,request,previous=None):
 result=ROOT/(name+'-result.json');pending=ROOT/(name+'-intent.json')
 if result.exists():return json.loads(result.read_text())
 assert not pending.exists(),'Unknown outcome for '+name+'; read-only reconcile before retry'
 intent={'action':action,'request_sha256':hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest(),'previous_setting':previous,'tags':OWNER,'client_token':request.get('ClientToken')};save(pending,intent);append({'phase':'intent','operation':name,**intent});response=aws(action,request);save(result,response);append({'phase':'result','operation':name,'resource_ids':ids(response),'result_sha256':hashlib.sha256(result.read_bytes()).hexdigest()});print('RECORDED '+name,flush=True);return response
def ids(value):
 found=[]
 if isinstance(value,dict):
  for k,v in value.items():
   if k.endswith('Id')and isinstance(v,str):found.append(v)
   else:found+=ids(v)
 elif isinstance(value,list):
  for x in value:found+=ids(x)
 return sorted(set(found))
def wait(name,fn):
 deadline=time.monotonic()+1200
 while True:
  if fn():print('READY '+name,flush=True);return
  assert time.monotonic()<deadline,name+' readiness timeout';print('WAIT '+name,flush=True);time.sleep(10)
assert json.loads(subprocess.check_output(['aws','sts','get-caller-identity','--output','json']))['Account']=='867703355911'
if not(ROOT/'baseline.json').exists():
 vpcs=aws('describe-vpcs')['Vpcs'];subnets=aws('describe-subnets')['Subnets'];vpns=aws('describe-vpn-connections',{'VpnConnectionIds':['vpn-05f16361b6265e541']})['VpnConnections'];gateway=aws('describe-instances',{'InstanceIds':['i-09d129f71f43119c7']})['Reservations'][0]['Instances'][0]
 assert all(v['CidrBlock']!='10.86.0.0/16'for v in vpcs)and all(s['CidrBlock']!='10.84.3.0/24'for s in subnets);assert gateway['PublicIpAddress']=='13.63.169.255'and gateway['PrivateIpAddress']=='10.84.1.10'and [x['GroupId']for x in gateway['SecurityGroups']]==['sg-026e49d0f7558609a']
 # Do not persist existing VPN secrets; keep only non-secret configuration/telemetry digest.
 vpn=vpns[0];save(ROOT/'baseline.json',{'gateway_id':gateway['InstanceId'],'gateway_groups':['sg-026e49d0f7558609a'],'gateway_eni':'eni-0fbe6981ac51bb28e','existing_vpn_id':vpn['VpnConnectionId'],'existing_vpn_state':vpn['State'],'existing_vpn_telemetry':vpn['VgwTelemetry'],'existing_routes':aws('describe-route-tables',{'Filters':[{'Name':'vpc-id','Values':['vpc-0446126a8e6d3fa0d','vpc-0c9344466ac5d9c7e']} ]})['RouteTables']})
target_vpc=mutate('target-vpc','create-vpc',{'CidrBlock':'10.86.0.0/16','TagSpecifications':tags('vpc','target-vpc')})['Vpc']['VpcId']
wait('target-vpc',lambda:aws('describe-vpcs',{'VpcIds':[target_vpc]})['Vpcs'][0]['State']=='available')
target_subnet=mutate('target-subnet','create-subnet',{'VpcId':target_vpc,'CidrBlock':'10.86.1.0/24','AvailabilityZone':'eu-north-1a','TagSpecifications':tags('subnet','target-subnet')})['Subnet']['SubnetId']
igw=mutate('target-igw','create-internet-gateway',{'TagSpecifications':tags('internet-gateway','target-igw')})['InternetGateway']['InternetGatewayId'];mutate('target-igw-attach','attach-internet-gateway',{'VpcId':target_vpc,'InternetGatewayId':igw})
rt=mutate('target-routes','create-route-table',{'VpcId':target_vpc,'TagSpecifications':tags('route-table','target-routes')})['RouteTable']['RouteTableId'];mutate('target-route-association','associate-route-table',{'SubnetId':target_subnet,'RouteTableId':rt});mutate('target-management-default','create-route',{'RouteTableId':rt,'DestinationCidrBlock':'0.0.0.0/0','GatewayId':igw},previous='absent')
tgw=mutate('tgw','create-transit-gateway',{'Description':OWNER,'Options':{'AmazonSideAsn':64512,'VpnEcmpSupport':'disable','DefaultRouteTableAssociation':'disable','DefaultRouteTablePropagation':'disable'},'TagSpecifications':tags('transit-gateway','tgw')})['TransitGateway']['TransitGatewayId'];wait('tgw',lambda:aws('describe-transit-gateways',{'TransitGatewayIds':[tgw]})['TransitGateways'][0]['State']=='available')
tgrt=mutate('tgw-routes','create-transit-gateway-route-table',{'TransitGatewayId':tgw,'TagSpecifications':tags('transit-gateway-route-table','tgw-routes')})['TransitGatewayRouteTable']['TransitGatewayRouteTableId']
attachment=mutate('target-attachment','create-transit-gateway-vpc-attachment',{'TransitGatewayId':tgw,'VpcId':target_vpc,'SubnetIds':[target_subnet],'TagSpecifications':tags('transit-gateway-attachment','target-attachment')})['TransitGatewayVpcAttachment']['TransitGatewayAttachmentId'];wait('target-attachment',lambda:aws('describe-transit-gateway-vpc-attachments',{'TransitGatewayAttachmentIds':[attachment]})['TransitGatewayVpcAttachments'][0]['State']=='available')
mutate('target-tgw-association','associate-transit-gateway-route-table',{'TransitGatewayRouteTableId':tgrt,'TransitGatewayAttachmentId':attachment});mutate('target-tgw-propagation','enable-transit-gateway-route-table-propagation',{'TransitGatewayRouteTableId':tgrt,'TransitGatewayAttachmentId':attachment})
if not(ROOT/'vpn-request-private.json').exists():
 tunnels=[]
 for cidr in ['169.254.120.0/30','169.254.120.4/30']:tunnels.append({'TunnelInsideCidr':cidr,'PreSharedKey':'S'+secrets.token_hex(24),'IKEVersions':[{'Value':'ikev2'}],'Phase1EncryptionAlgorithms':[{'Value':'AES256'}],'Phase2EncryptionAlgorithms':[{'Value':'AES256'}],'Phase1IntegrityAlgorithms':[{'Value':'SHA2-256'}],'Phase2IntegrityAlgorithms':[{'Value':'SHA2-256'}],'Phase1DHGroupNumbers':[{'Value':14}],'Phase2DHGroupNumbers':[{'Value':14}],'Phase1LifetimeSeconds':28800,'Phase2LifetimeSeconds':3600})
 save(ROOT/'vpn-request-private.json',{'Type':'ipsec.1','CustomerGatewayId':'cgw-052420797aa1518a1','TransitGatewayId':tgw,'Options':{'StaticRoutesOnly':False,'TunnelInsideIpVersion':'ipv4','TunnelOptions':tunnels},'TagSpecifications':tags('vpn-connection','dynamic-vpn')})
vpn=mutate('vpn','create-vpn-connection',json.loads((ROOT/'vpn-request-private.json').read_text()))['VpnConnection']['VpnConnectionId']
# VPN asynchronously provisions while fresh target/client instances initialize.
def sg(name,vpc,permissions):
 group=mutate(name+'-sg','create-security-group',{'GroupName':OWNER+'-'+name,'Description':OWNER+' '+name,'VpcId':vpc,'TagSpecifications':tags('security-group',name)})['GroupId']
 mutate(name+'-sg-ingress','authorize-security-group-ingress',{'GroupId':group,'IpPermissions':permissions,'TagSpecifications':tags('security-group-rule',name+'-ingress')});return group
def tcp(port,cidr):return {'IpProtocol':'tcp','FromPort':port,'ToPort':port,'IpRanges':[{'CidrIp':cidr}]}
targetsg=sg('target',target_vpc,[tcp(22,'16.170.207.192/32'),tcp(8080,'10.84.3.0/24')])
userdata='''#!/bin/bash
set -eu
install -d -m700 /opt/tunnex-tgw
cat > /opt/tunnex-tgw/echo.py <<'EOF'
import hashlib,http.server,json,re,urllib.parse
class Echo(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  nonce=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('nonce',[''])[0]
  if not re.fullmatch('[0-9a-f]{64}',nonce):self.send_error(400);return
  data=json.dumps({'nonce':nonce,'sha256':hashlib.sha256(nonce.encode()).hexdigest(),'target':'10.86.1.10'}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
http.server.ThreadingHTTPServer(('0.0.0.0',8080),Echo).serve_forever()
EOF
chmod 700 /opt/tunnex-tgw/echo.py
cat > /etc/systemd/system/tunnex-tgw-echo.service <<'EOF'
[Unit]
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/tunnex-tgw/echo.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now tunnex-tgw-echo
'''
def instance(name,subnet,ip,group,user_data=None):
 req={'ImageId':'ami-09d835910a77f135c','InstanceType':'t3.micro','MinCount':1,'MaxCount':1,'KeyName':'tunnex-bgp-20261007-key','NetworkInterfaces':[{'DeviceIndex':0,'SubnetId':subnet,'PrivateIpAddress':ip,'Groups':[group],'AssociatePublicIpAddress':True}],'MetadataOptions':{'HttpTokens':'required','HttpEndpoint':'enabled'},'TagSpecifications':tags('instance',name)+tags('volume',name+'-volume'),'ClientToken':OWNER+'-'+name}
 if user_data:req['UserData']=base64.b64encode(user_data.encode()).decode()
 return mutate(name+'-instance','run-instances',req)['Instances'][0]['InstanceId']
target=None if network_only else instance('target',target_subnet,'10.86.1.10',targetsg,userdata)
clientsubnet=mutate('client-subnet','create-subnet',{'VpcId':'vpc-0446126a8e6d3fa0d','CidrBlock':'10.84.3.0/24','AvailabilityZone':'eu-north-1a','TagSpecifications':tags('subnet','client-subnet')})['Subnet']['SubnetId'];clientrt=mutate('client-routes','create-route-table',{'VpcId':'vpc-0446126a8e6d3fa0d','TagSpecifications':tags('route-table','client-routes')})['RouteTable']['RouteTableId'];mutate('client-route-association','associate-route-table',{'SubnetId':clientsubnet,'RouteTableId':clientrt});mutate('client-target-route','create-route',{'RouteTableId':clientrt,'DestinationCidrBlock':'10.86.0.0/16','NetworkInterfaceId':'eni-0fbe6981ac51bb28e'},previous='absent');mutate('client-management-default','create-route',{'RouteTableId':clientrt,'DestinationCidrBlock':'0.0.0.0/0','GatewayId':'igw-07f50007aa6330df5'},previous='absent');clientsg=sg('client','vpc-0446126a8e6d3fa0d',[tcp(22,'16.170.207.192/32')]);client=None if network_only else instance('client',clientsubnet,'10.84.3.10',clientsg)
wait('vpn',lambda:aws('describe-vpn-connections',{'VpnConnectionIds':[vpn]})['VpnConnections'][0]['State']=='available');current=aws('describe-vpn-connections',{'VpnConnectionIds':[vpn]})['VpnConnections'][0];
if not(ROOT/'vpn-current-private.json').exists():save(ROOT/'vpn-current-private.json',current)
else:
 saved=json.loads((ROOT/'vpn-current-private.json').read_text());assert saved['VpnConnectionId']==current['VpnConnectionId']and saved['TransitGatewayId']==current['TransitGatewayId']and saved['CustomerGatewayId']==current['CustomerGatewayId']and [x['OutsideIpAddress']for x in saved['Options']['TunnelOptions']]==[x['OutsideIpAddress']for x in current['Options']['TunnelOptions']]
vpnattachments=aws('describe-transit-gateway-attachments',{'Filters':[{'Name':'resource-id','Values':[vpn]},{'Name':'transit-gateway-id','Values':[tgw]}]})['TransitGatewayAttachments'];assert len(vpnattachments)==1;vpnattachment=vpnattachments[0]['TransitGatewayAttachmentId'];append({'phase':'discovered','operation':'vpn-attachment','resource_ids':[vpnattachment]});wait('vpn-attachment',lambda:aws('describe-transit-gateway-attachments',{'TransitGatewayAttachmentIds':[vpnattachment]})['TransitGatewayAttachments'][0]['State']=='available')
mutate('vpn-tgw-association','associate-transit-gateway-route-table',{'TransitGatewayRouteTableId':tgrt,'TransitGatewayAttachmentId':vpnattachment});mutate('vpn-tgw-propagation','enable-transit-gateway-route-table-propagation',{'TransitGatewayRouteTableId':tgrt,'TransitGatewayAttachmentId':vpnattachment});mutate('target-client-route','create-route',{'RouteTableId':rt,'DestinationCidrBlock':'10.84.3.0/24','TransitGatewayId':tgw},previous='absent')
peers=[x['OutsideIpAddress']for x in current['Options']['TunnelOptions']];assert len(peers)==2
permissions=[tcp(8080,'10.84.3.0/24')]+[{'IpProtocol':'udp','FromPort':port,'ToPort':port,'IpRanges':[{'CidrIp':ip+'/32'}for ip in peers]}for port in [500,4500]];gatewaysg=sg('gateway-tgw','vpc-0446126a8e6d3fa0d',permissions)
instances=[]
if not network_only:
 wait('instances-running',lambda:all(x['State']['Name']=='running'for r in aws('describe-instances',{'InstanceIds':[target,client]})['Reservations']for x in r['Instances']))
 instances=[x for r in aws('describe-instances',{'InstanceIds':[target,client]})['Reservations']for x in r['Instances']]
summary={'owner':OWNER,'target_vpc':target_vpc,'target_subnet':target_subnet,'target_routes':rt,'target_igw':igw,'tgw':tgw,'tgw_routes':tgrt,'target_attachment':attachment,'vpn':vpn,'vpn_attachment':vpnattachment,'outside_peers':peers,'inside':['169.254.120.0/30','169.254.120.4/30'],'target_sg':targetsg,'client_sg':clientsg,'gateway_sg_NOT_ATTACHED':gatewaysg,'client_subnet':clientsubnet,'client_routes':clientrt,'target_instance':target,'client_instance':client,'instances':[{'id':x['InstanceId'],'private':x['PrivateIpAddress'],'public':x['PublicIpAddress']}for x in instances],'gateway_groups_unchanged':[x['GroupId']for x in aws('describe-network-interfaces',{'NetworkInterfaceIds':['eni-0fbe6981ac51bb28e']})['NetworkInterfaces'][0]['Groups']]};assert summary['gateway_groups_unchanged']==['sg-026e49d0f7558609a'];save(ROOT/('summary-network-only.json'if network_only else'summary.json'),summary);print(json.dumps(summary),flush=True)
