# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative '../scripts/import-threatfox'

class ThreatFoxFallbackTest < Minitest::Test
  def importer(output:, key: nil)
    instance = ThreatFoxImporter.new(['fetch', '--output', output])
    instance.instance_variable_set(:@options, {
      output: output,
      snapshot: nil,
      days: 3,
      limit: nil,
      report_json: nil,
      overrides_file: nil
    })
    instance.define_singleton_method(:http_post_json) do |_url, _body, _headers|
      if key == :rejected
        raise 'HTTP 401 for https://threatfox-api.abuse.ch/api/v1/'
      else
        { 'query_status' => 'no_auth_key', 'data' => [] }
      end
    end if %i[rejected response].include?(key)
    instance
  end

  def write_snapshot(root, date, payload, query_status: 'ok')
    path = File.join(root, date)
    Dir.mkdir(path)
    File.write(File.join(path, 'get_iocs.json'), JSON.pretty_generate(payload))
    File.write(File.join(path, 'manifest.yml'), <<~YAML)
      query_status: #{query_status}
      retrieved_at: '2026-08-31T03:00:00Z'
      record_count: #{Array(payload['data']).size}
    YAML
    path
  end

  def test_missing_key_reuses_last_known_good_snapshot_with_stale_metadata
    Dir.mktmpdir do |root|
      payload = { 'query_status' => 'ok', 'data' => [{ 'id' => 7 }] }
      prior = write_snapshot(root, '2026-08-31', payload)
      output = File.join(root, '2026-09-01')

      importer(output: output).send(:fetch_snapshot)

      assert_equal payload, JSON.parse(File.read(File.join(output, 'get_iocs.json')))
      manifest = YAML.safe_load(File.read(File.join(output, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal 'stale_fallback', manifest['query_status']
      assert_equal 'no_auth_key', manifest['fallback_reason']
      assert_equal prior, manifest['fallback_snapshot']
    end
  end

  def test_rejected_key_reuses_last_known_good_snapshot_with_stale_metadata
    Dir.mktmpdir do |root|
      payload = { 'query_status' => 'ok', 'data' => [{ 'id' => 8 }] }
      write_snapshot(root, '2026-08-31', payload)
      output = File.join(root, '2026-09-01')

      ENV['THREATFOX_API_KEY'] = 'invalid-test-key'
      importer(output: output, key: :rejected).send(:fetch_snapshot)

      assert_equal payload, JSON.parse(File.read(File.join(output, 'get_iocs.json')))
      assert_includes File.read(File.join(output, 'manifest.yml')), 'fallback_reason: auth_failed'
    ensure
      ENV.delete('THREATFOX_API_KEY')
    end
  end

  def test_missing_key_without_prior_snapshot_marks_source_unavailable
    Dir.mktmpdir do |root|
      output = File.join(root, '2026-09-01')
      importer(output: output).send(:fetch_snapshot)

      assert_equal({ 'query_status' => 'source_unavailable', 'data' => [] },
                   JSON.parse(File.read(File.join(output, 'get_iocs.json'))))
      manifest = YAML.safe_load(File.read(File.join(output, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal 'source_unavailable', manifest['query_status']
      assert_equal 'no_auth_key', manifest['fallback_reason']
      assert_equal 0, manifest['record_count']
    end
  end

  def test_auth_failure_payload_reuses_last_known_good_snapshot
    Dir.mktmpdir do |root|
      payload = { 'query_status' => 'ok', 'data' => [{ 'id' => 9 }] }
      write_snapshot(root, '2026-08-31', payload)
      output = File.join(root, '2026-09-01')
      ENV['THREATFOX_API_KEY'] = 'invalid-test-key'

      importer(output: output, key: :response).send(:fetch_snapshot)

      assert_equal payload, JSON.parse(File.read(File.join(output, 'get_iocs.json')))
    ensure
      ENV.delete('THREATFOX_API_KEY')
    end
  end

  def test_retry_preserves_valid_current_snapshot
    Dir.mktmpdir do |root|
      payload = { 'query_status' => 'ok', 'data' => [{ 'id' => 10 }] }
      output = write_snapshot(root, '2026-09-01', payload)

      importer(output: output).send(:fetch_snapshot)

      assert_equal payload, JSON.parse(File.read(File.join(output, 'get_iocs.json')))
      manifest = YAML.safe_load(File.read(File.join(output, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal output, manifest['fallback_snapshot']
    end
  end

  def test_import_provenance_preserves_stale_retrieval_metadata
    importer = ThreatFoxImporter.new(['import', '--snapshot', '/tmp/snapshot'])
    actor = { 'name' => 'Example', 'malware' => ['Example'], 'iocs' => {} }
    rows = [{ 'id' => 12, 'ioc' => 'example.test', 'ioc_type' => 'domain', 'malware' => 'Example' }]
    plan = [{ match: { position: 0, confidence: :high } }]
    manifest = {
      'retrieved_at' => '2026-09-02T04:00:00Z',
      'source_retrieved_at' => '2026-08-31T03:00:00Z',
      'query_status' => 'stale_fallback',
      'fallback_reason' => 'auth_failed',
      'fallback_snapshot' => '/tmp/snapshot/2026-08-31'
    }

    actor_store = ActorStore.method(:save_all)
    enrichment = MitreAttackGroupEnrichment.method(:append_source!)
    ActorStore.define_singleton_method(:save_all) { |_actors| nil }
    MitreAttackGroupEnrichment.define_singleton_method(:append_source!) { |_actor, _source, **_options| nil }
    importer.send(:apply_matches, rows, plan, [actor], '/tmp/snapshot/2026-09-02', manifest)

    provenance = actor.dig('provenance', 'threatfox')
    assert_equal '2026-08-31T03:00:00Z', provenance['source_retrieved_at']
    assert_equal 'stale_fallback', provenance['source_status']
    assert_equal 'auth_failed', provenance['fallback_reason']
    assert_equal '/tmp/snapshot/2026-08-31', provenance['fallback_snapshot']
  ensure
    ActorStore.define_singleton_method(:save_all, actor_store) if actor_store
    MitreAttackGroupEnrichment.define_singleton_method(:append_source!, enrichment) if enrichment
  end

  def test_malformed_newer_manifest_is_skipped
    Dir.mktmpdir do |root|
      payload = { 'query_status' => 'ok', 'data' => [{ 'id' => 11 }] }
      valid = write_snapshot(root, '2026-08-30', payload)
      malformed = File.join(root, '2026-08-31')
      Dir.mkdir(malformed)
      File.write(File.join(malformed, 'get_iocs.json'), JSON.pretty_generate({ 'data' => [] }))
      File.write(File.join(malformed, 'manifest.yml'), "---\n- malformed\n")
      File.utime(Time.now, Time.now + 1, malformed)
      output = File.join(root, '2026-09-01')

      importer(output: output).send(:fetch_snapshot)

      manifest = YAML.safe_load(File.read(File.join(output, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal valid, manifest['fallback_snapshot']
    end
  end

  def test_name_and_tag_coincidence_cannot_create_actor_match
    instance = importer(output: Dir.mktmpdir)
    actors = [{ 'name' => 'LockBit', 'url' => '/lockbit', 'malware' => [{ 'name' => 'LockBit' }] }]
    ioc = { 'malware' => 'win.lockbit', 'malware_printable' => 'LockBit', 'tags' => ['lockbit'] }

    assert_empty instance.send(:candidate_keys_for_ioc, ioc, actors)
    assert_nil instance.send(:match_ioc_to_actor, ioc, actors, { 'lockbit' => [0] })[:position]
  end

  def test_only_explicit_reviewed_mapping_can_create_actor_match
    instance = importer(output: Dir.mktmpdir)
    instance.instance_variable_set(:@overrides, {
      'malware_slug_overrides' => {
        'win.lockbit' => { 'actor_slug' => 'lockbit', 'reviewed_by' => 'analyst', 'reviewed_at' => '2026-09-02' }
      }
    })
    actors = [{ 'name' => 'LockBit', 'url' => '/lockbit' }]

    match = instance.send(:match_ioc_to_actor, { 'malware' => 'win.lockbit' }, actors, { 'lockbit' => [0] })
    assert_equal 0, match[:position]
  end

  def test_apply_matches_rechecks_review_gate_before_publishing
    instance = importer(output: Dir.mktmpdir)
    actors = [{ 'name' => 'LockBit', 'url' => '/lockbit', 'iocs' => {} }]
    rows = [{ 'id' => 1, 'ioc' => '198.51.100.10', 'ioc_type' => 'ipv4', 'malware' => 'win.lockbit' }]
    plan_rows = [{ match: { position: 0, confidence: :high } }]
    saved = nil

    ActorStore.stub(:save_all, ->(value) { saved = value }) do
      instance.send(:apply_matches, rows, plan_rows, actors, '/tmp/snapshot')
    end

    assert_equal({}, saved.first['iocs'])
  end
end
