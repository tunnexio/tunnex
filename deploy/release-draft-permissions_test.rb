# Executes the real prepublication script with a permission-aware GitHub fixture.
# This proves workflow wiring, not GitHub's live authorization implementation.
require 'yaml'
require 'json'
require 'tmpdir'
require 'open3'
require 'minitest/autorun'

class ReleaseDraftPermissionsTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  CI = YAML.load_file(ENV.fetch('TUNNEX_CI_CONTRACT_FILE', File.join(ROOT, '.github/workflows/ci.yml')))
  JOB = CI.fetch('jobs').fetch('publish')
  SOURCE = 'a' * 40

  def test_draft_readers_have_write_permission
    %w[release-version-guard publish release-assets].each do |name|
      assert_equal 'write', CI.fetch('jobs').fetch(name).fetch('permissions').fetch('contents'), name
    end
    assert_equal false, JOB.fetch('steps').find { |s| s['uses'] == 'actions/checkout@v4' }
      .fetch('with').fetch('persist-credentials')
  end

  def test_publication_stays_push_only_and_guarded
    condition = JOB.fetch('if')
    ["github.event_name == 'push'", "vars.TUNNEX_RELEASE_PUBLISH_ENABLED == 'true'",
     "github.ref == 'refs/heads/main'", "startsWith(github.ref, 'refs/tags/v')",
     "needs.release-version-guard.result == 'success'", "needs.gates.result == 'success'",
     "needs.e2e.result == 'success'", "needs.e2e-enterprise.result == 'success'"].each do |guard|
      assert_includes condition, guard
    end
    assert_equal %w[release-version-guard gates e2e e2e-enterprise], JOB.fetch('needs')
    refute JOB['continue-on-error']
    step = JOB.fetch('steps').first
    assert_equal 'Revalidate release source ledger immediately before image publication', step.fetch('name')
    assert_equal '${{ secrets.GITHUB_TOKEN }}', step.fetch('env').fetch('GH_TOKEN')
    refute step['continue-on-error']
  end

  def run_guard(permission:, scenario:, ref: 'refs/heads/main')
    Dir.mktmpdir('tunnex-draft-permission-') do |dir|
      File.write(File.join(dir, 'gh'), <<~'SH')
        #!/usr/bin/env bash
        set -eu
        case "$*" in
          'api '*'/commits/'*)
            if [ "$FIXTURE_CASE" = moved ]; then printf '%040d\n' 0; else echo "$GITHUB_SHA"; fi ;;
          'release view '*)
            if [ "$FIXTURE_PERMISSION" != write ] || [ "$FIXTURE_CASE" = absent ]; then
              echo 'release not found' >&2; exit 1
            fi
            if [ "$FIXTURE_CASE" = published ]; then echo false; else echo true; fi ;;
          'release download '*)
            if [ "$FIXTURE_PERMISSION" != write ]; then exit 1; fi
            if [ "$FIXTURE_CASE" = ledger ]; then echo '{}'; else
              jq -cn --arg tag "$FIXTURE_TAG" --arg source_sha "$GITHUB_SHA" '{schema_version:1,tag:$tag,source_sha:$source_sha}'
            fi ;;
          *) echo 'unexpected GitHub mutation/call' >&2; exit 90 ;;
        esac
      SH
      File.chmod(0o700, File.join(dir, 'gh'))
      tag = ref.start_with?('refs/tags/') ? ref.delete_prefix('refs/tags/') : "tunnex-build-#{SOURCE}"
      env = { 'PATH' => "#{dir}:#{ENV.fetch('PATH')}", 'FIXTURE_PERMISSION' => permission,
        'FIXTURE_CASE' => scenario, 'FIXTURE_TAG' => tag, 'GITHUB_SHA' => SOURCE,
        'GITHUB_REF' => ref, 'GITHUB_REF_NAME' => ref.split('/').last,
        'GITHUB_REPOSITORY' => 'tunnexio/tunnex', 'GH_TOKEN' => 'offline-fixture' }
      Open3.capture3(env, 'bash', '-eu', '-o', 'pipefail', '-c', JOB.fetch('steps').first.fetch('run'))
    end
  end

  def test_actual_workflow_permissions_accept_matching_draft_for_main_and_tag
    ['refs/heads/main', 'refs/tags/v9.8.7'].each do |ref|
      _, stderr, status = run_guard(permission: JOB.fetch('permissions').fetch('contents'),
        scenario: 'matching', ref: ref)
      assert status.success?, stderr
    end
  end

  def test_original_read_only_permission_reproduces_release_not_found
    _, stderr, status = run_guard(permission: 'read', scenario: 'matching')
    refute status.success?
    assert_includes stderr, 'release not found'
  end

  def test_guards_still_refuse_absent_published_moved_and_wrong_ledger
    %w[absent published moved ledger].each do |scenario|
      _, _, status = run_guard(permission: 'write', scenario: scenario)
      refute status.success?, scenario
    end
    _, _, status = run_guard(permission: 'write', scenario: 'matching', ref: 'refs/pull/1/merge')
    refute status.success?
  end
end
