require 'yaml'
require 'json'
require 'tmpdir'
require 'open3'
require 'minitest/autorun'

class VerifyInstallerSiteTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  SOURCE = 'a' * 40
  CI = YAML.load_file(File.join(ROOT, '.github/workflows/ci.yml'))
  RELEASE = CI.fetch('jobs').fetch('release-assets')
  STEPS = RELEASE.fetch('steps')
  GATE_NAME = 'Verify deployed platform installers before tagged release promotion'
  PROMOTION_NAME = 'Publish only the completed source-ledger release'

  def fixture(scenario, ref: 'refs/tags/v9.8.7')
    Dir.mktmpdir('tunnex-installer-site-test-') do |dir|
      canonical = 'https://raw.githubusercontent.com/tunnexio/tunnex/main/deploy/install.sh'
      launcher = File.binread(File.join(ROOT, 'deploy/get.sh'))
      live = launcher.sub(canonical, canonical.sub('/main/', "/#{SOURCE}/"))
      powershell = File.binread(File.join(ROOT, 'deploy/install.ps1'))
      case scenario
      when 'stale' then live = live.sub(SOURCE, 'b' * 40)
      when 'wrong-launcher' then live += "\n# changed bytes\n"
      when 'html' then live = '<html>not an installer</html>'
      when 'wrong-powershell' then powershell += "\n# changed bytes\n"
      when 'missing-bom'
        raise 'PowerShell fixture must preserve the shipped BOM' unless powershell.start_with?("\xEF\xBB\xBF".b)
        powershell = powershell.byteslice(3..-1)
      end
      File.binwrite(File.join(dir, 'get.sh'), live)
      File.binwrite(File.join(dir, 'install.ps1'), powershell)
      File.write(File.join(dir, 'curl'), <<~'SH')
        #!/bin/sh
        set -eu
        destination= url=
        while [ "$#" -gt 0 ]; do
          case "$1" in
            -o) destination=$2; shift 2 ;;
            https://*) url=$1; shift ;;
            *) shift ;;
          esac
        done
        printf '%s\n' "$url" >> "$FIXTURE_DIR/requests"
        case "$url" in
          https://get.tunnex.io)
            [ "$FIXTURE_SCENARIO" != get-error ] || exit 22
            cp "$FIXTURE_DIR/get.sh" "$destination" ;;
          https://get.tunnex.io/install.ps1)
            [ "$FIXTURE_SCENARIO" != powershell-error ] || exit 22
            cp "$FIXTURE_DIR/install.ps1" "$destination" ;;
          *) echo 'unexpected network destination' >&2; exit 90 ;;
        esac
      SH
      tag = ref.start_with?('refs/tags/') ? ref.delete_prefix('refs/tags/') : "tunnex-build-#{SOURCE}"
      File.write(File.join(dir, 'ledger.json'), JSON.generate({ schema_version: 1, tag: tag, source_sha: SOURCE }))
      File.write(File.join(dir, 'gh'), <<~'SH')
        #!/bin/sh
        set -eu
        case "$*" in
          'api '*'/commits/'*) echo "$GITHUB_SHA" ;;
          'release view '*)
            if [ -f "$FIXTURE_DIR/promoted" ]; then echo false; else echo true; fi ;;
          'release download '*) cat "$FIXTURE_DIR/ledger.json" ;;
          'release edit '*) printf '%s\n' "$*" > "$FIXTURE_DIR/promoted" ;;
          *) echo 'unexpected release operation' >&2; exit 90 ;;
        esac
      SH
      %w[curl gh].each { |name| File.chmod(0o700, File.join(dir, name)) }
      env = { 'PATH' => "#{dir}:#{ENV.fetch('PATH')}", 'FIXTURE_DIR' => dir,
        'FIXTURE_SCENARIO' => scenario, 'GITHUB_SHA' => SOURCE, 'GITHUB_REF' => ref,
        'GITHUB_REF_NAME' => ref.split('/').last, 'GITHUB_REPOSITORY' => 'tunnexio/tunnex' }
      yield env, dir
    end
  end

  def test_public_bytes_include_exact_source_pin_and_windows_bom
    fixture('matching') do |env, dir|
      output, err, status = Open3.capture3(env, 'sh', File.join(ROOT, 'deploy/verify-installer-site.sh'), SOURCE)
      assert status.success?, err
      assert_includes output, SOURCE
      assert_equal %w[https://get.tunnex.io https://get.tunnex.io/install.ps1], File.readlines(File.join(dir, 'requests'), chomp: true)
    end
  end

  def test_rejects_unavailable_stale_or_changed_public_installers
    %w[get-error powershell-error stale wrong-launcher html wrong-powershell missing-bom].each do |scenario|
      fixture(scenario) do |env, _|
        _, error, status = Open3.capture3(env, 'sh', File.join(ROOT, 'deploy/verify-installer-site.sh'), SOURCE)
        refute status.success?, scenario
        assert_match(/error:/, error, scenario)
      end
    end
  end

  def test_rejects_invalid_source_before_network_access
    ['', 'a' * 39, 'A' * 40, '../main'].each do |source|
      fixture('matching') do |env, dir|
        _, _, status = Open3.capture3(env.merge('GITHUB_SHA' => ''), 'sh', File.join(ROOT, 'deploy/verify-installer-site.sh'), source)
        refute status.success?, source
        refute File.exist?(File.join(dir, 'requests'))
      end
    end
  end

  def test_workflow_runs_gate_directly_before_promotion_only_for_tags
    index = STEPS.index { |s| s['name'] == GATE_NAME }
    refute_nil index
    gate = STEPS.fetch(index)
    assert_equal "startsWith(github.ref, 'refs/tags/v')", gate.fetch('if')
    assert_equal 'sh deploy/verify-installer-site.sh "$GITHUB_SHA"', gate.fetch('run')
    refute gate['continue-on-error']
    refute RELEASE['continue-on-error']
    promotion = STEPS.fetch(index + 1)
    assert_equal PROMOTION_NAME, promotion.fetch('name')
    refute promotion.key?('if'), 'promotion must retain the default success-only condition'
    refute promotion['continue-on-error']
    assert_equal index + 1, STEPS.length - 1
    contract = CI.fetch('jobs').fetch('contracts').fetch('steps').find { |s| s['name'] == 'Public installer release promotion contract' }
    assert_equal 'ruby deploy/verify-installer-site_test.rb', contract.fetch('run')
  end

  def run_release_steps(env)
    gate = STEPS.find { |s| s['name'] == GATE_NAME }.fetch('run')
    promotion = STEPS.find { |s| s['name'] == PROMOTION_NAME }.fetch('run')
    # Execute both production scripts with the workflow's tested tag condition.
    script = "set -euo pipefail\ncd \"$FIXTURE_ROOT\"\nif [[ \"$GITHUB_REF\" == refs/tags/v* ]]; then\n#{gate}\nfi\n#{promotion}"
    Open3.capture3(env.merge('FIXTURE_ROOT' => ROOT), 'bash', '-c', script)
  end

  def test_failed_gate_leaves_the_release_as_a_draft
    %w[get-error powershell-error stale wrong-launcher wrong-powershell missing-bom].each do |scenario|
      fixture(scenario) do |env, dir|
        _, _, status = run_release_steps(env)
        refute status.success?, scenario
        refute File.exist?(File.join(dir, 'promoted')), scenario
        output, _, check = Open3.capture3(env, 'gh', 'release', 'view', 'v9.8.7', '--json', 'isDraft', '--jq', '.isDraft')
        assert check.success?, scenario
        assert_equal "true\n", output, scenario
      end
    end
  end

  def test_matching_site_allows_existing_source_ledger_promotion
    fixture('matching') do |env, dir|
      _, err, status = run_release_steps(env)
      assert status.success?, err
      assert_equal "release edit v9.8.7 --draft=false --latest\n", File.read(File.join(dir, 'promoted'))
    end
  end

  def test_main_prerelease_does_not_wait_for_website_sync
    fixture('get-error', ref: 'refs/heads/main') do |env, dir|
      _, err, status = run_release_steps(env)
      assert status.success?, err
      refute File.exist?(File.join(dir, 'requests'))
      assert_equal "release edit tunnex-build-#{SOURCE} --draft=false --prerelease --latest=false\n", File.read(File.join(dir, 'promoted'))
    end
  end
end
