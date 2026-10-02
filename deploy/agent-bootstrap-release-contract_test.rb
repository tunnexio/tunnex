#!/usr/bin/env ruby
# Exercise the actual publication step with a closed GitHub/Go fixture. Crypto
# and downloaded-byte validation are covered by the Go release tool tests.
require 'yaml'
require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'open3'
require 'json'

class AgentBootstrapReleaseContract < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  CI = YAML.load_file(File.join(ROOT, '.github/workflows/ci.yml'))

  def steps(job)
    CI.fetch('jobs').fetch(job).fetch('steps')
  end

  def step(job, name)
    steps(job).find { |s| s['name'] == name } || raise("missing workflow step #{name}")
  end

  def test_architectures_signing_and_ordering
    build = step('cli-release', 'Build Linux managed-agent release verifiers').fetch('run')
    assert_includes build, 'for arch in amd64 arm64'
    assert_includes build, 'CGO_ENABLED=0 GOOS=linux GOARCH="$arch"'
    assert_includes build, './cmd/releaseverify'
    upload = step('cli-release', 'Upload Linux managed-agent runtime artifacts')
    assert_includes upload.fetch('if'), "github.ref == 'refs/heads/main'"
    %w[amd64 arm64].each { |a| assert_includes upload.fetch('with').fetch('path'), "runtime-artifacts/releaseverify-linux-#{a}" }
    sign = step('release-assets', 'Build and sign the immutable release manifest').fetch('run')
    assert_includes sign, 'go run ./cmd/releasesign -bootstrap-verifier'
    assert_includes sign, 'purpose:"tunnex-agent-bootstrap-verifier"'
    assert_includes sign, '-bootstrap-verifier-assets ../../runtime-artifacts'
    assert_includes sign, 'sha256sum runtime-artifacts/releaseverify-linux-amd64'
    assert_includes sign, 'sha256sum runtime-artifacts/releaseverify-linux-arm64'
    names = steps('release-assets').map { |s| s['name'] }
    assert_operator names.index('Attach and verify managed-agent bootstrap verifier assets'), :<, names.index('Publish only the completed source-ledger release')
    descriptor_step = step('release-assets', 'Attach and verify managed-agent bootstrap verifier assets')
    refute descriptor_step.key?('if'), 'verifier assets must publish for both main and tags'
    assert_includes File.read(File.join(ROOT, 'apps/api/internal/release/bootstrap_verifier.go')), 'DisallowUnknownFields'
    refute_includes File.read(File.join(ROOT, 'apps/api/internal/release/manifest.go')), 'BootstrapVerifier'
  end

  def run_publication(ref, refusal = '')
    Dir.mktmpdir('agent-verifier-publication') do |dir|
      FileUtils.mkdir_p(File.join(dir, 'apps/api'))
      FileUtils.mkdir_p(File.join(dir, 'bin'))
      File.write(File.join(dir, 'release-verification-public-key.txt'), "public-fixture-key\n")
      %w[gh go].each do |command|
        File.write(File.join(dir, 'bin', command), <<~'SH')
          #!/usr/bin/env bash
          set -euo pipefail
          printf '%s %s\n' "${0##*/}" "$*" >> "$FIXTURE_LOG"
          if [[ "${0##*/}" == go ]]; then
            [[ "$*" == *'-expected-source-sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'* ]]
            [[ "$*" == *'-bootstrap-verifier ../../verifier-publication-check/agent-bootstrap-verifier.json'* ]]
            [[ "$*" == *'-bootstrap-verifier-assets ../../verifier-publication-check'* ]]
            [[ "$REFUSAL" != invalid-downloaded-bytes ]]
            exit
          fi
          case "$1 $2" in
            'api repos/'*)
              if [[ "$REFUSAL" == moved-source ]]; then printf '%040d\n' 0; else printf '%s\n' "$GITHUB_SHA"; fi ;;
            'release view')
              if [[ "$REFUSAL" == published ]]; then echo false; else echo true; fi ;;
            'release download')
              if [[ "$*" == *'Tunnex-release-source.json'* ]]; then
                source="$GITHUB_SHA"; [[ "$REFUSAL" != wrong-ledger ]] || source=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
                jq -cn --arg tag "$3" --arg source_sha "$source" '{schema_version:1,tag:$tag,source_sha:$source_sha}'
              else
                [[ "$*" == *'--pattern release.json --pattern agent-bootstrap-verifier.json --pattern releaseverify-linux-amd64 --pattern releaseverify-linux-arm64'* ]]
                [[ "$REFUSAL" != missing-download ]]
              fi ;;
            'release upload')
              [[ "$*" == *'agent-bootstrap-verifier.json runtime-artifacts/releaseverify-linux-amd64 runtime-artifacts/releaseverify-linux-arm64 --clobber'* ]] ;;
            *) exit 20 ;;
          esac
        SH
        File.chmod(0o755, File.join(dir, 'bin', command))
      end
      env = { 'PATH' => "#{dir}/bin:#{ENV.fetch('PATH')}", 'GITHUB_SHA' => 'a' * 40,
              'GITHUB_REPOSITORY' => 'tunnexio/fixture', 'GITHUB_REF' => ref,
              'GITHUB_REF_NAME' => ref.split('/').last, 'TUNNEX_RELEASE_KEY_ID' => 'fixture',
              'FIXTURE_LOG' => File.join(dir, 'commands'), 'REFUSAL' => refusal }
      output, status = Open3.capture2e(env, 'bash', '-c', step('release-assets', 'Attach and verify managed-agent bootstrap verifier assets').fetch('run'), chdir: dir)
      log = File.read(File.join(dir, 'commands'))
      [status.success?, log, output]
    end
  end

  def test_main_and_tag_downloaded_assets_verified
    %w[refs/heads/main refs/tags/v1.2.3].each do |ref|
      ok, log, output = run_publication(ref)
      assert ok, output
      tag = ref.end_with?('main') ? "tunnex-build-#{'a' * 40}" : 'v1.2.3'
      assert_includes log, "gh release upload #{tag} agent-bootstrap-verifier.json"
      assert_includes log, 'go run ./cmd/releaseverify'
    end
  end

  def test_guard_and_download_failures_stop_publication
    %w[moved-source published wrong-ledger missing-download invalid-downloaded-bytes].each do |refusal|
      ok, log, output = run_publication('refs/tags/v1.2.3', refusal)
      refute ok, "accepted #{refusal}: #{output}"
      refute_includes log, 'gh release upload' if %w[moved-source published wrong-ledger].include?(refusal)
    end
  end
end
