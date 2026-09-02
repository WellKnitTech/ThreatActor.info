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

  def test_missing_key_without_prior_snapshot_still_fails_closed
    Dir.mktmpdir do |root|
      error = assert_raises(RuntimeError) { importer(output: File.join(root, '2026-09-01')).send(:fetch_snapshot) }
      assert_includes error.message, 'no_auth_key'
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
end
