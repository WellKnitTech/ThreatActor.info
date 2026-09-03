# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'json_schemer'
require 'yaml'
require_relative '../scripts/canonical_observables'

class CanonicalObservablesTest < Minitest::Test
  ROOT = File.expand_path('fixtures/observables', __dir__)

  def setup
    @valid = YAML.safe_load(File.read(File.join(ROOT, 'valid-observables.yml'))).fetch('observations')
    @invalid = YAML.safe_load(File.read(File.join(ROOT, 'invalid-observables.yml'))).fetch('cases')
  end

  def test_valid_fixture_canonicalizes_and_deduplicates
    records = CanonicalObservables.canonicalize_all(@valid.reject { |row| row['status'] == 'false_positive' })
    assert_equal @valid.length - 1, records.length
    assert_equal 'c2.example.com', records.find { |r| r['type'] == 'domain' }['value']
    assert_equal 2, records.find { |r| r['type'] == 'domain' }['sources'].length
    assert_equal 'CVE-2024-12345', records.find { |r| r['type'] == 'cve' }['value']
    assert records.all? { |r| r['id'].start_with?('obs_v1_') }
    assert_equal records.map { |r| r['id'] }, CanonicalObservables.canonicalize_all(@valid.reject { |row| row['status'] == 'false_positive' }).map { |r| r['id'] }
    schema = JSONSchemer.schema(JSON.parse(File.read(File.expand_path('../schemas/observable.schema.json', __dir__))))
    assert records.all? { |record| schema.valid?(record) }
    assert_equal 'quarantined', records.find { |r| r['value'] == 'conflict.example' }['status']
    refute CanonicalObservables.public?(records.find { |r| r['value'] == 'stale.example' })
  end

  def test_invalid_fixture_fails_closed_with_expected_reasons
    @invalid.each do |row|
      error = assert_raises(ArgumentError) { CanonicalObservables.canonicalize(row) }
      assert_equal row['reason'], error.message, row['name']
    end
  end

  def test_false_positive_is_not_public
    record = CanonicalObservables.canonicalize(@valid.find { |row| row['status'] == 'false_positive' })
    refute CanonicalObservables.public?(record)
  end

  def test_legacy_lists_remain_readable_by_existing_reader
    require_relative '../scripts/ioc_yaml_reader'
    actor = YAML.safe_load(File.read(File.join(ROOT, 'legacy-actor.yml')))
    rows = IocYamlReader.indicator_rows_from_actor(actor)
    assert_equal 1, rows.count { |row| row[:inferred_type] == 'domain' }
    assert_equal 1, rows.count { |row| row[:inferred_type] == 'md5' }
  end
end
