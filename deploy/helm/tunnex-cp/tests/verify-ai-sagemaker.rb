#!/usr/bin/env ruby
# Rendering only: no Kubernetes API, provider credential or model request.
require 'json'
require 'yaml'
require 'open3'
require 'tempfile'
chart = File.expand_path('..', __dir__)
args = ['--set', 'database.urlSecret=db-fixture', '--set', 'redis.urlSecret=redis-fixture', '--set', 'masterKey.existingSecret=master-fixture', '--set', 'appBaseURL=https://fixture.invalid']
base = {'aiGateway'=>{'enabled'=>true, 'engineImage'=>'ghcr.io/tunnexio/tunnex-ai-engine@sha256:'+'a'*64, 'providerManagementEnabled'=>true, 'existingSecret'=>'ai-fixture', 'customProviders'=>{'enabled'=>true, 'publicHTTPS'=>true, 'existingSecret'=>'proxy-fixture', 'endpoints'=>[{'name'=>'SageMaker', 'provider'=>'sagemaker', 'url'=>'https://runtime.us-east-1.amazonaws.com', 'allowed_cidrs'=>['10.20.0.0/24']}]}, 'sagemaker'=>{'enabled'=>true, 'endpointURL'=>'https://runtime.us-east-1.amazonaws.com', 'existingSecret'=>'aws-fixture', 'models'=>[{'alias'=>'model-a', 'endpoint'=>'endpoint-a', 'region'=>'us-east-1', 'access_key_id_env'=>'AWS_ACCESS', 'secret_access_key_env'=>'AWS_SECRET', 'role_arn'=>'arn:aws:iam::123456789012:role/fixture'}], 'clients'=>[{'key_env'=>'CLIENT_KEY', 'models'=>['model-a']}]}}}
render = lambda do |values, valid=true|
  Tempfile.create(['sagemaker', '.json']) do |file|
    file.write(JSON.generate(values)); file.flush
    output, error, status = Open3.capture3('helm', 'template', 'native-contract', chart, *args, '-f', file.path)
    raise "render outcome mismatch #{error}" unless status.success? == valid
    valid ? YAML.load_stream(output).compact : []
  end
end
documents = render.call(base)
engine = documents.find { |d| d['kind']=='Deployment' && d.dig('metadata','name')=='native-contract-tunnex-cp-ai' }.dig('spec','template','spec','containers')[0]
raise 'mutable/stock runtime' unless engine['image']==base['aiGateway']['engineImage']
%w[AWS_ACCESS AWS_SECRET CLIENT_KEY].each do |name|
  ref = engine['env'].find { |e| e['name']==name }
  raise 'credential leaked or wrong owner' unless ref.dig('valueFrom','secretKeyRef')=={'name'=>'aws-fixture', 'key'=>name}
end
raise 'config mount not read-only' unless engine['volumeMounts'].any? { |v| v['name']=='sagemaker' && v['readOnly'] }
api = documents.find { |d| d['kind']=='Deployment' && d.dig('metadata','name')=='api' }.dig('spec','template','spec','containers')[0]
raise 'provider secret reached CP' if api['env'].any? { |e| %w[AWS_ACCESS AWS_SECRET CLIENT_KEY].include?(e['name']) }
raise 'second inference runtime rendered' if documents.any? { |d| d.dig('metadata','name').to_s.include?('ai-bridge') || d.dig('metadata','name')=='litellm-bridge' }
cfg = JSON.parse(documents.find { |d| d['kind']=='ConfigMap' && d.dig('metadata','name')=='native-contract-tunnex-cp-ai-sagemaker' }['data']['config.json'])
raise 'model/client scope lost' unless cfg['models']==base['aiGateway']['sagemaker']['models'] && cfg['clients']==base['aiGateway']['sagemaker']['clients']
[
  ['engineImage', 'native:latest'], ['sagemaker.existingSecret', ''],
  ['sagemaker.endpointURL', 'http://169.254.169.254'], ['customProviders.enabled', false]
].each do |path, value|
  bad = Marshal.load(Marshal.dump(base)); keys=path.split('.'); parent=bad['aiGateway']
  keys[0...-1].each { |key| parent=parent[key] }; parent[keys[-1]]=value
  render.call(bad, false)
end
puts 'PASS: one native engine; retained scoped SageMaker bindings; engine-only credential refs; explicit endpoint/egress; mutable images and incomplete configuration refused'
