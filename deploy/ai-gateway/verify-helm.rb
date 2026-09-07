#!/usr/bin/env ruby
# Static Helm rendering only; no Kubernetes calls or credential values.
require 'open3'
require 'yaml'
require 'json'
root = File.expand_path('../..', __dir__)
chart = File.join(root, 'deploy/helm/tunnex-cp')
args = ['--set', 'database.urlSecret=db-fixture', '--set', 'redis.urlSecret=redis-fixture', '--set', 'masterKey.existingSecret=master-fixture', '--set', 'appBaseURL=https://fixture.invalid']
render = lambda do |extra=[]|
  output, err, status = Open3.capture3('helm', 'template', 'ai-contract', chart, *args, *extra)
  raise err unless status.success?
  YAML.load_stream(output).compact
end
base = render.call
raise 'AI resources appeared by default' if base.any? { |d| d.dig('metadata', 'name').to_s.include?('-ai') || d.dig('metadata', 'name') == 'bifrost' }
enabled = render.call(['--set', 'aiGateway.enabled=true', '--set', 'aiGateway.existingSecret=ai-fixture'])
select = lambda { |kind, name| enabled.find { |d| d['kind'] == kind && d.dig('metadata', 'name') == name } || raise("missing #{kind}/#{name}") }
service = select.call('Service', 'bifrost')
raise 'engine publicly exposed' unless service.dig('spec', 'type') == 'ClusterIP' && !service.dig('spec', 'externalIPs') && service.dig('spec', 'ports').none? { |p| p['nodePort'] }
engine = select.call('Deployment', 'ai-contract-tunnex-cp-ai')
raise 'engine not single instance' unless engine.dig('spec', 'replicas') == 1 && engine.dig('spec', 'strategy', 'type') == 'Recreate'
container = engine.dig('spec', 'template', 'spec', 'containers')[0]
raise 'pin changed' unless container['image'] == 'maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208'
%w[BIFROST_ADMIN_USER BIFROST_ADMIN_PASSWORD OPENROUTER_API_KEY BIFROST_ENCRYPTION_KEY].each do |name|
  env = container['env'].find { |e| e['name'] == name }
  raise 'secret inlined or missing' unless env.dig('valueFrom', 'secretKeyRef', 'name') == 'ai-fixture' && !env.key?('value')
end
api_env = select.call('Deployment', 'api').dig('spec', 'template', 'spec', 'containers')[0]['env']
raise 'provider credential reached API' if api_env.any? { |e| e['name'] == 'OPENROUTER_API_KEY' }
raise 'wrong private origin' unless api_env.find { |e| e['name'] == 'TUNNEX_AI_GATEWAY_URL' }['value'] == 'http://bifrost:8080'
%w[config logs].each do |kind|
  pvc = select.call('PersistentVolumeClaim', "ai-contract-tunnex-cp-ai-#{kind}")
  raise 'PVC not retained' unless pvc.dig('metadata', 'annotations', 'helm.sh/resource-policy') == 'keep'
end
policy = select.call('NetworkPolicy', 'ai-contract-tunnex-cp-ai')
raise 'wrong policy modes' unless policy.dig('spec', 'policyTypes').sort == %w[Egress Ingress]
peer = policy.dig('spec', 'ingress')[0]['from'][0]
raise 'non-CP ingress allowed' unless peer == {'podSelector'=>{'matchLabels'=>{'app.kubernetes.io/instance'=>'ai-contract', 'app.kubernetes.io/component'=>'api'}}}
egress = policy.dig('spec', 'egress')
raise 'egress must have only DNS and HTTPS rules' unless egress.length == 2
raise 'DNS ports broadened' unless egress[0]['ports'].map { |p| [p['protocol'], p['port']] }.sort == [['TCP',53],['UDP',53]]
raise 'DNS selector missing' unless egress[0]['to'][0].key?('namespaceSelector') && egress[0]['to'][0].key?('podSelector')
raise 'HTTPS ports broadened' unless egress[1]['ports'] == [{'protocol'=>'TCP','port'=>443}]
raise 'private CIDRs not excluded' unless egress[1]['to'][0]['ipBlock']['except'].include?('169.254.0.0/16') && egress[1]['to'][0]['ipBlock']['except'].include?('10.0.0.0/8')
config = JSON.parse(select.call('ConfigMap', 'ai-contract-tunnex-cp-ai')['data']['config.json'])
raise 'content logging or open inference' unless config.dig('client','disable_content_logging') && config.dig('client','enforce_auth_on_inference')
raise 'bootstrap keys granted' unless config.dig('governance','virtual_keys') == []
nginx = select.call('ConfigMap', 'ai-contract-tunnex-cp-ai-edge')['data']['default.conf']
raise 'SSE proxy missing' unless nginx.include?('location /ai/') && nginx.include?('proxy_buffering off;') && nginx.include?('proxy_read_timeout 35s;')
raise 'Docker DNS used in Kubernetes' if nginx.include?('127.0.0.11')
[['--set','aiGateway.enabled=true'], ['--set','aiGateway.enabled=true','--set','aiGateway.existingSecret=ai-fixture','--set','api.replicas=2']].each do |bad|
  _, _, status = Open3.capture3('helm', 'template', 'ai-contract', chart, *args, *bad)
  raise 'unsafe values accepted' if status.success?
end
_, error, status = Open3.capture3('helm', 'lint', chart, *args, '--set', 'aiGateway.enabled=true', '--set', 'aiGateway.existingSecret=ai-fixture')
raise error unless status.success?
puts 'PASS: default-off Helm; pinned private single engine; secret refs; retained PVCs; CP-only ingress; required DNS/public HTTPS egress; SSE edge; missing secret/HA refused; helm lint'

managed = render.call(['--set', 'aiGateway.enabled=true', '--set', 'aiGateway.existingSecret=ai-fixture', '--set', 'aiGateway.providerManagementEnabled=true'])
managed_config = managed.find { |d| d['kind'] == 'ConfigMap' && d.dig('metadata','name') == 'ai-contract-tunnex-cp-ai' }
raise 'managed providers remain file-owned' if JSON.parse(managed_config['data']['config.json']).key?('providers')
managed_api = managed.find { |d| d['kind'] == 'Deployment' && d.dig('metadata','name') == 'api' }
raise 'management not explicitly enabled' unless managed_api.dig('spec','template','spec','containers')[0]['env'].any? { |e| e['name'] == 'TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED' && e['value'] == 'true' }
managed_engine = managed.find { |d| d['kind'] == 'Deployment' && d.dig('metadata','name') == 'ai-contract-tunnex-cp-ai' }
provider_ref = managed_engine.dig('spec','template','spec','containers')[0]['env'].find { |e| e['name'] == 'OPENROUTER_API_KEY' }
raise 'fresh managed install requires legacy provider key' unless provider_ref.dig('valueFrom','secretKeyRef','optional') == true
raise 'legacy references not preserved' unless provider_ref.dig('valueFrom','secretKeyRef','key') == 'openrouter-api-key'
raise 'legacy management unexpectedly on' unless api_env.any? { |e| e['name'] == 'TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED' && e['value'] == 'false' }
puts 'PASS: managed Helm opt-in removes provider stanza, preserves optional legacy key references and persistent state'

require 'tempfile'
Tempfile.create(['ai-custom', '.json']) do |file|
  file.write(JSON.generate({'aiGateway'=>{'enabled'=>true, 'existingSecret'=>'ai-fixture', 'providerManagementEnabled'=>true, 'customProviders'=>{'enabled'=>true, 'existingSecret'=>'proxy-fixture', 'endpoints'=>[{'name'=>'Private fixture','url'=>'https://inference.internal','allowed_cidrs'=>['10.20.0.0/24']}], 'protectedHosts'=>['control.internal'], 'deniedCIDRs'=>['10.21.0.0/24']}}})); file.flush
  custom = render.call(['-f',file.path])
  api = custom.find { |d| d['kind']=='Deployment' && d.dig('metadata','name')=='api' }
  containers = api.dig('spec','template','spec','containers')
  proxy = containers.find { |c| c['name']=='ai-egress' }
  raise 'missing private sidecar' unless proxy && proxy['image']==containers[0]['image'] && proxy['command']==['/usr/local/bin/tunnex-ai-egress']
  raise 'proxy received CP secrets' unless proxy['env'].map { |e| e['name'] }.sort==%w[TUNNEX_AI_CUSTOM_ENDPOINTS_FILE TUNNEX_AI_CUSTOM_PROXY_LISTEN TUNNEX_AI_CUSTOM_PROXY_PASSWORD TUNNEX_AI_CUSTOM_PROXY_USERNAME]
  raise 'proxy received secret mounts' unless proxy['volumeMounts']==[{'name'=>'ai-custom-policy','mountPath'=>'/etc/tunnex/ai-custom','readOnly'=>true}]
  engine = custom.find { |d| d['kind']=='Deployment' && d.dig('metadata','name')=='ai-contract-tunnex-cp-ai' }
  [containers[0],engine.dig('spec','template','spec','containers')[0]].each do |c|
    ref=c['env'].find { |e| e['name']=='TUNNEX_AI_CUSTOM_PROXY_URL' }
    raise 'proxy URL not shared secret ref' unless ref.dig('valueFrom','secretKeyRef')=={'name'=>'proxy-fixture','key'=>'proxy-url'}
  end
  cfg=custom.find { |d| d['kind']=='ConfigMap' && d.dig('metadata','name')=='ai-contract-tunnex-cp-ai-custom' }
  policy=JSON.parse(cfg['data']['policy.json'])
  raise 'mandatory protected services missing' unless %w[api bifrost control.internal].all? { |h| policy['protected_hosts'].include?(h) }
  svc=custom.find { |d| d['kind']=='Service' && d.dig('metadata','name')=='api' }
  raise 'proxy service not private' unless svc.dig('spec','type')=='ClusterIP' && svc.dig('spec','ports').any? { |p| p['port']==8190 && !p['nodePort'] }
  net=custom.find { |d| d['kind']=='NetworkPolicy' }
  proxy_rule=net.dig('spec','egress').find { |r| r['ports']==[{'protocol'=>'TCP','port'=>8190}] }
  raise 'proxy egress broadened' unless proxy_rule['to']==[{'podSelector'=>{'matchLabels'=>{'app.kubernetes.io/instance'=>'ai-contract','app.kubernetes.io/component'=>'api'}}}]
end
[['aiGateway.enabled=false'], ['aiGateway.enabled=true','aiGateway.providerManagementEnabled=false'], ['aiGateway.enabled=true','aiGateway.providerManagementEnabled=true']].each do |settings|
  flags=settings.flat_map { |s| ['--set',s] }
  _, _, status=Open3.capture3('helm','template','ai-contract',chart,*args,'--set','aiGateway.customProviders.enabled=true','--set','aiGateway.existingSecret=ai-fixture',*flags)
  raise 'incomplete custom setup accepted' if status.success?
end
puts 'PASS: custom opt-in sidecar isolation, shared secret refs, protected policy, private service and scoped egress; incomplete setup refused'
