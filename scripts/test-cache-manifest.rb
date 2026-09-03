# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative 'lib/import/cache_manifest'
require_relative 'import-mitre'

class CacheManifestTest < Minitest::Test
  def test_manifest_records_stable_hashes_and_metrics_without_secrets
    manifest = SourceImport::CacheManifest.build(
      source_key: 'example', retrieved_at: '2026-09-03T12:00:00Z',
      records: [{ 'id' => 'two', 'value' => 2 }, { 'id' => 'one', 'value' => 1 }],
      validators: { etag: '"abc"', authorization: 'must-not-leak' },
      metrics: { 'request_count' => 2, 'response_bytes' => 99 }
    )

    assert_equal %w[etag], manifest['request_validators'].keys
    assert_equal 2, manifest['record_hashes'].size
    assert_equal false, manifest['secrets_present']
    assert_equal 99, manifest.dig('metrics', 'response_bytes')
  end

  def test_corrupt_or_wrong_schema_manifests_are_ignored
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'cache-manifest.yml')
      File.write(path, "not: a cache manifest\n")
      assert_nil SourceImport::CacheManifest.load(path)
      File.write(path, YAML.dump('cache_schema_version' => '0.0', 'secrets_present' => false))
      assert_nil SourceImport::CacheManifest.load(path)
    end
  end

  def test_atomic_write_round_trips
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'nested', 'manifest.yml')
      manifest = SourceImport::CacheManifest.build(source_key: 'x', retrieved_at: '2026-09-03T12:00:00Z')
      SourceImport::CacheManifest.write_atomic(path, manifest)
      assert_equal manifest, SourceImport::CacheManifest.load(path)
      refute File.exist?("#{path}.tmp-#{Process.pid}")
    end
  end

  def test_mitre_reuses_only_matching_version_and_verified_bundle
    Dir.mktmpdir do |root|
      previous = File.join(root, '2026-09-02')
      current = File.join(root, '2026-09-03')
      FileUtils.mkdir_p(previous)
      bundle = File.join(previous, 'enterprise-attack.json')
      File.write(bundle, '{"objects":[]}')
      SourceImport::CacheManifest.write_atomic(
        File.join(previous, 'cache-manifest.yml'),
        SourceImport::CacheManifest.build(
          source_key: 'mitre-attack', retrieved_at: '2026-09-02T12:00:00Z',
          source_version: '15.0', bundles: {
            'enterprise' => { 'content_sha256' => Digest::SHA256.file(bundle).hexdigest }
          }
        )
      )
      importer = MitreAttackImporter.new(['fetch'])
      importer.instance_variable_set(:@options, { output: current, version: '15.0' })
      assert_equal bundle, importer.send(:reusable_bundle, 'enterprise', 'enterprise-attack.json')[:path]
      importer.instance_variable_get(:@options)[:version] = '16.0'
      assert_nil importer.send(:reusable_bundle, 'enterprise', 'enterprise-attack.json')
    end
  end
end
