require 'yaml'
require 'json'
require 'tmpdir'
require 'open3'
require 'minitest/autorun'

class NativeImagePublicationTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  CI = YAML.load_file(File.join(ROOT, '.github/workflows/ci.yml'))
  def test_native_lanes_and_publication_dependency
    job = CI.fetch('jobs').fetch('node-native')
    assert_equal [['amd64', 'ubuntu-24.04'], ['arm64', 'ubuntu-24.04-arm']],
      job.fetch('strategy').fetch('matrix').fetch('include').map { |m| m.values_at('arch', 'runner') }
    refute job.fetch('steps').any? { |s| s.fetch('uses', '').include?('setup-qemu') }
    build = job.fetch('steps').find { |s| s['id'] == 'build' }.fetch('with')
    assert_includes build.fetch('outputs'), "push=${{ github.event_name == 'push' }}"
    assert_includes build.fetch('cache-to'), '${{ matrix.arch }}'
    assert_includes job.fetch('if'), "github.event_name == 'pull_request'"
    publish = CI.fetch('jobs').fetch('publish')
    assert_includes publish.fetch('needs'), 'node-native'
    assert_includes publish.fetch('if'), "needs.node-native.result == 'success'"
    assert_equal "matrix.image.name != 'node-agent' && matrix.image.name != 'ai-engine'", publish.fetch('steps').find { |s| s['id'] == 'build' }.fetch('if')
    assert_includes publish.fetch('steps').last.fetch('with').fetch('subject-digest'), 'steps.node-index.outputs.digest'
    # Native digest uploads inherit precisely the same source-ledger check.
    assert_equal publish.fetch('steps').first.fetch('run'), job.fetch('steps').first.fetch('run')
    assert_equal "github.event_name == 'push'", job.fetch('steps').first.fetch('if')
    assert CI.fetch('jobs').fetch('contracts').fetch('steps').any? { |s| s['run'] == 'ruby deploy/release-draft-permissions_test.rb' },
      'required contracts must run the draft release permission regression'
  end

  def test_operator_compiles_on_build_host_for_explicit_target
    dockerfile = File.read(File.join(ROOT, 'apps/operator/Dockerfile'))
    assert_match(/^FROM --platform=\$BUILDPLATFORM golang:/, dockerfile)
    assert_includes dockerfile, 'ARG TARGETOS'
    assert_includes dockerfile, 'ARG TARGETARCH'
    assert_includes dockerfile, 'GOOS=$TARGETOS GOARCH=$TARGETARCH go build'
    assert_includes dockerfile, 'CGO_ENABLED=0'
    build = CI.fetch('jobs').fetch('publish').fetch('steps').find { |s| s['id'] == 'build' }.fetch('with')
    assert_includes build.fetch('cache-to'), 'timeout=2m,ignore-error=true'
  end

  def test_web_builds_shared_assets_natively_and_retains_both_runtime_platforms
    dockerfile = File.read(File.join(ROOT, 'deploy/docker/web.Dockerfile'))
    # The shared frontend and cross-compiled client set must not be rebuilt by
    # emulated target toolchains; nginx still follows the requested platform.
    assert_match(/^FROM --platform=\$BUILDPLATFORM golang:.* AS editor-client$/, dockerfile)
    assert_match(/^FROM --platform=\$BUILDPLATFORM node:.* AS build$/, dockerfile)
    assert_match(/^FROM nginxinc\/nginx-unprivileged:/, dockerfile)
    assert_includes dockerfile, 'CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build'
    assert_includes dockerfile, 'for os in darwin linux; do for arch in amd64 arm64; do'
    assert_includes dockerfile, 'COPY --from=editor-client /editor-client /usr/share/nginx/html/editor-client'
    build = CI.fetch('jobs').fetch('publish').fetch('steps').find { |s| s['id'] == 'build' }.fetch('with')
    assert_equal 'linux/amd64,linux/arm64', build.fetch('platforms')
  end

  def run_merge(scenario)
    Dir.mktmpdir do |d|
      digests = File.join(d, 'digests'); Dir.mkdir(digests)
      File.write(File.join(digests, 'a' * 64), '')
      File.write(File.join(digests, 'b' * 64), '') unless scenario == 'missing'
      File.write(File.join(d, 'docker'), <<~'SH')
        #!/usr/bin/env bash
        set -eu
        if [[ "$*" == *'inspect --raw'* ]]; then
          arch=amd64
          if [[ "$*" == *bbbbbbbb* && "$SCENARIO" != duplicate ]]; then arch=arm64; fi
          printf '{"manifests":[{"platform":{"os":"linux","architecture":"%s"}},{"platform":{"os":"unknown","architecture":"unknown"}}]}\n' "$arch"
        elif [[ "$*" == *'imagetools create'* ]]; then
          echo called > "$MARKER"
          while [[ $# -gt 0 ]]; do
            if [[ "$1" == --metadata-file ]]; then
              printf '{"containerimage.descriptor":{"digest":"sha256:%064d"}}\n' 0 > "$2"
            fi
            shift
          done
        else exit 99; fi
      SH
      File.chmod(0755, File.join(d, 'docker'))
      marker = File.join(d, 'called')
      output = File.join(d, 'output')
      env = { 'PATH' => "#{d}:#{ENV['PATH']}", 'IMAGE' => 'ghcr.io/tunnexio/tunnex-node-agent',
        'TAGS' => "ghcr.io/tunnexio/tunnex-node-agent:latest\nghcr.io/tunnexio/tunnex-node-agent:sha-example",
        'GITHUB_OUTPUT' => output, 'SCENARIO' => scenario, 'MARKER' => marker }
      _, err, status = Open3.capture3(env, 'bash', File.join(ROOT, 'deploy/publish-node-index.sh'), digests)
      [status.success?, File.exist?(marker), File.exist?(output) ? File.read(output) : '', err]
    end
  end
  def test_combines_both_platforms_and_returns_digest
    ok, published, output, err = run_merge('valid')
    assert ok, err
    assert published
    assert_match(/^digest=sha256:[a-f0-9]{64}$/, output.strip)
  end
  def test_native_ai_engine_retains_source_platform_and_release_guards
    job = CI.fetch('jobs').fetch('ai-native')
    assert_equal [['amd64', 'ubuntu-24.04'], ['arm64', 'ubuntu-24.04-arm']],
      job.fetch('strategy').fetch('matrix').fetch('include').map { |m| m.values_at('arch', 'runner') }
    refute job.fetch('steps').any? { |s| s.fetch('uses', '').include?('setup-qemu') }
    assert_operator job.fetch('timeout-minutes'), :>=, 60
    build = job.fetch('steps').find { |s| s['id'] == 'build' }.fetch('with')
    assert_equal '.', build.fetch('context')
    assert_equal 'apps/ai-engine/Dockerfile', build.fetch('file')
    assert_equal 'linux/${{ matrix.arch }}', build.fetch('platforms')
    assert_includes build.fetch('outputs'), 'name=ghcr.io/${{ github.repository }}-ai-engine'
    assert_includes build.fetch('outputs'), "push=${{ github.event_name == 'push' }}"
    publish = CI.fetch('jobs').fetch('publish')
    assert_equal publish.fetch('steps').first.fetch('run'), job.fetch('steps').first.fetch('run')
    assert_includes publish.fetch('if'), "needs.ai-native.result == 'success'"
    assert_includes publish.fetch('needs'), 'ai-native'
    assert_includes publish.fetch('steps').last.fetch('with').fetch('subject-digest'), 'steps.ai-index.outputs.digest'
    anonymous = CI.fetch('jobs').fetch('publish-pullable').fetch('steps').find { |s| s['run'] }.fetch('run')
    images = anonymous[/^IMAGES="([^"]+)"$/, 1]
    refute_nil images, 'anonymous-pull check must declare its image list'
    assert_includes images.split, 'ai-engine'
    manifest = CI.fetch('jobs').fetch('release-assets').fetch('steps').find { |s| s['name'] == 'Build and sign the immutable release manifest' }.fetch('run')
    assert_includes manifest, '"ai-engine":{linux_amd64_digest:$ai_amd64,linux_arm64_digest:$ai_arm64}'
    dockerfile = File.read(File.join(ROOT, 'apps/ai-engine/Dockerfile'))
    assert_includes dockerfile, 'extension/build.py /build/source /build/engine --test'
    assert_includes dockerfile, '/app/catalog/'
    refute_includes dockerfile, 'pip install'
  end
  def test_refuses_incomplete_or_duplicate_platforms_before_tagging
    %w[missing duplicate].each do |scenario|
      ok, published, = run_merge(scenario)
      refute ok, scenario
      refute published, scenario
    end
  end
end
