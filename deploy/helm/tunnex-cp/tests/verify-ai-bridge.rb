#!/usr/bin/env ruby
# Rendering only; no Kubernetes or container operations.
require 'json'
require 'yaml'
require 'open3'
require 'tempfile'
chart=File.expand_path('..',__dir__)
args=['--set','database.urlSecret=db-fixture','--set','redis.urlSecret=redis-fixture','--set','masterKey.existingSecret=master-fixture','--set','appBaseURL=https://fixture.invalid']
base={'aiGateway'=>{'enabled'=>true,'providerManagementEnabled'=>true,'existingSecret'=>'ai-fixture','customProviders'=>{'enabled'=>true,'existingSecret'=>'proxy-fixture','endpoints'=>[{'name'=>'Bridge','provider'=>'sagemaker','url'=>'http://litellm-bridge:8200','allowed_cidrs'=>['10.20.0.0/24']}]},'litellmBridge'=>{'enabled'=>true,'image'=>'registry.invalid/bridge@sha256:'+'a'*64,'existingSecret'=>'bridge-fixture','models'=>[{'alias'=>'model-a','endpoint'=>'endpoint-a','region'=>'us-east-1','access_key_id_env'=>'AWS_ACCESS','secret_access_key_env'=>'AWS_SECRET','role_arn'=>'arn:aws:iam::123456789012:role/fixture'}],'clients'=>[{'key_env'=>'CLIENT_KEY','models'=>['model-a']}]}}}
render=lambda do |values, valid=true|
  Tempfile.create(['bridge','.json']) do |f|
    f.write(JSON.generate(values));f.flush
    out,err,status=Open3.capture3('helm','template','bridge-contract',chart,*args,'-f',f.path)
    raise "render outcome mismatch #{err}" unless status.success? == valid
    valid ? YAML.load_stream(out).compact : []
  end
end
docs=render.call(base)
select=lambda { |kind,name| docs.find { |d| d['kind']==kind && d.dig('metadata','name')==name } || raise("missing #{kind}/#{name}") }
deploy=select.call('Deployment','bridge-contract-tunnex-cp-ai-bridge')
pod=deploy.dig('spec','template','spec');c=pod['containers'][0]
raise 'service token mounted' unless pod['automountServiceAccountToken']==false
raise 'mutable image' unless c['image']==base['aiGateway']['litellmBridge']['image']
raise 'bridge state writable' unless c.dig('securityContext','readOnlyRootFilesystem')
raise 'secret shared with CP or leaked' unless c['env'].map { |e| e['name'] }.sort==%w[AWS_ACCESS AWS_SECRET CLIENT_KEY TUNNEX_AI_BRIDGE_ADMIN_TOKEN TUNNEX_AI_BRIDGE_CONFIG_FILE TUNNEX_AI_BRIDGE_LISTEN TUNNEX_AI_CUSTOM_ENDPOINTS_FILE TUNNEX_AI_CUSTOM_PROXY_URL]
%w[AWS_ACCESS AWS_SECRET CLIENT_KEY].each { |n| raise 'wrong secret ref' unless c['env'].find { |e| e['name']==n }.dig('valueFrom','secretKeyRef')=={'name'=>'bridge-fixture','key'=>n} }
raise 'missing shared policy' unless c['volumeMounts'].any? { |v| v['name']=='policy' && v['readOnly'] }
service=select.call('Service','litellm-bridge');raise 'public bridge' unless service.dig('spec','type')=='ClusterIP' && service.dig('spec','ports')==[{'name'=>'http','port'=>8200,'targetPort'=>'http'}]
net=select.call('NetworkPolicy','bridge-contract-tunnex-cp-ai-bridge')
raise 'broad ingress' unless net.dig('spec','ingress')==[{'from'=>[{'podSelector'=>{'matchLabels'=>{'app.kubernetes.io/instance'=>'bridge-contract','app.kubernetes.io/component'=>'api'}}}],'ports'=>[{'protocol'=>'TCP','port'=>8200}]}]
raise 'egress expanded' unless net.dig('spec','egress').map { |r| r['ports'].map { |p| p['port'] } }==[[53,53],[443],[8190]]
api=select.call('Deployment','api').dig('spec','template','spec','containers')[0]
raise 'API bridge URL missing' unless api['env'].any? { |e| e=={'name'=>'TUNNEX_AI_LITELLM_URL','value'=>'http://litellm-bridge:8200'} }
raise 'AWS secret reached API' if api['env'].any? { |e| %w[AWS_ACCESS AWS_SECRET CLIENT_KEY].include?(e['name']) }
[['image','bridge:latest'],['existingSecret','']].each do |key,value|
 bad=Marshal.load(Marshal.dump(base));bad['aiGateway']['litellmBridge'][key]=value;render.call(bad,false)
end
bad=Marshal.load(Marshal.dump(base));bad['aiGateway']['customProviders']['enabled']=false;render.call(bad,false)
_,err,status=Open3.capture3('helm','lint',chart,*args);raise err unless status.success?
puts 'PASS: immutable opt-in bridge; isolated secrets/config; private service; API-only ingress; DNS/public HTTPS/proxy egress; invalid image/secret/SageMaker policy refused; lint'
