#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative 'lib/import/source_adapter'

class SourceAdapterContractTest < Minitest::Test
  def test_result_rejects_unknown_status_but_preserves_unknown_diagnostic_codes
    assert_raises(ArgumentError) { SourceImport::Result.new(status: 'mystery') }

    diagnostic = SourceImport::Diagnostic.new(code: 'future_code', message: 'new parser signal', severity: 'warning')
    assert_equal false, diagnostic[:known_code]
    assert_equal 'future_code', diagnostic[:code]
  end

  def test_json_round_trip_is_deterministic_and_value_objects_are_immutable
    result = SourceImport::ValidationResult.new(status: 'partial', counts: { records: 2 }, warnings: ['skipped'])
    first = result.to_json
    second = SourceImport::ValidationResult.new(status: 'partial', counts: { records: 2 }, warnings: ['skipped']).to_json
    assert_equal first, second
    assert result.frozen?
    assert_raises(FrozenError) { result[:warnings] << 'another' }
  end

  def test_plan_checksum_and_snapshot_binding_are_deterministic
    plan = SourceImport::Plan.new(snapshot_checksum: 'snap-1', catalog_revision: 'catalog-1',
                                  operations: [{ actor: 'a', action: 'add_alias' }])
    assert_equal plan.plan_checksum, SourceImport::Plan.new(snapshot_checksum: 'snap-1', catalog_revision: 'catalog-1',
                                                             operations: [{ actor: 'a', action: 'add_alias' }]).plan_checksum
    assert plan.compatible_with?(snapshot_checksum: 'snap-1', catalog_revision: 'catalog-1')
    refute plan.compatible_with?(snapshot_checksum: 'snap-2', catalog_revision: 'catalog-1')
  end

  def test_manifest_and_report_include_machine_readable_lifecycle_fields
    manifest = SourceImport::SnapshotManifest.new(source_key: 'example', snapshot_id: 's1',
                                                   retrieved_at: '2026-08-16T12:00:00Z', source_url: 'https://example.test')
    result = SourceImport::Result.new(status: 'quarantined', diagnostics: [{ code: 'parser_empty', message: 'no records' }])
    report = SourceImport::RunReport.new(run_id: 'run-1', source_key: 'example', phase: 'validate', result: result)
    assert_equal 'example', manifest[:source_key]
    assert_equal 'quarantined', report[:status]
    assert_equal 'parser_empty', report[:diagnostics].first[:code]
  end

  def test_legacy_adapter_maps_existing_lifecycle_without_writes_in_fetch_or_plan
    legacy = Class.new do
      def fetch(_context) = { records: [] }
      def plan(_snapshot, _catalog, _context) = { operations: [] }
      def apply(_plan, _writer, _context) = :applied
    end.new
    adapter = SourceImport::LegacyAdapter.new(source_key: 'legacy', legacy: legacy)
    assert_equal 'ok', adapter.fetch[:status]
    assert_equal({ records: [] }, adapter.fetch[:data])
    assert_equal({ operations: [] }, adapter.plan({}, {}, {})[:data])
  end
end
