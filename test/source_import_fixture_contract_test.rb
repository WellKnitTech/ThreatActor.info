# frozen_string_literal: true

require 'minitest/autorun'
require 'nokogiri'
require 'tmpdir'
require 'yaml'
require_relative 'support/source_fixture_harness'
require_relative '../scripts/import-unit42-threat-actor-groups'
require_relative '../scripts/import-dragos-threat-groups'
require_relative '../scripts/snapshot_quality_gate'

class SourceImportFixtureContractTest < Minitest::Test
  include SourceFixtureHarness

  def test_unit42_canonical_fixture_preserves_counts_and_provenance
    importer = Unit42ThreatActorGroupsImporter.new([])
    records = importer.send(:parse_actors_from_html, html('unit42', 'canonical'))

    assert_contract self, 'unit42', 'canonical', contract('unit42', records)
    assert_equal %w[APT29 Cozy\ Bear Tick], records.flat_map { |row| row['aliases'] }.sort
  end

  def test_unit42_canonical_fixture_matches_existing_actor_by_alias
    existing = [{ 'name' => 'APT 29', 'aliases' => ['SilverTerrier', 'Cozy Bear'] }]
    index = ImportUtils.build_alias_index(existing)
    match = ImportUtils.find_match('SilverTerrier', ['APT29'], index)

    assert_equal :high, match[:confidence]
    assert_equal 0, match[:position]
  end

  def test_unit42_changed_layout_is_explicitly_represented_by_fixture_contract
    expected_contract = expected('unit42', 'changed-layout')

    assert_equal 'accepted', expected_contract['status']
    assert_equal 2, expected_contract.dig('counts', 'records')
    assert_equal 'Palo Alto Networks Unit 42 Threat Actor Groups', expected_contract.dig('provenance', 'source_name')
  end

  def test_unit42_empty_and_malformed_snapshots_quarantine
    importer = Unit42ThreatActorGroupsImporter.new([])

    %w[empty malformed].each do |case_name|
      records = importer.send(:parse_actors_from_html, html('unit42', case_name))
      assert_contract self, 'unit42', case_name, contract('unit42', records)
    end
  end

  def test_dragos_canonical_fixture_resolves_detail_pages_and_provenance
    Dir.mktmpdir('dragos-fixture') do |tmpdir|
      FileUtils.cp_r(fixture('dragos', 'canonical'), tmpdir)
      importer = DragosThreatGroupsImporter.new([])
      importer.instance_variable_set(:@options, { output: File.join(tmpdir, 'canonical') })
      document = Nokogiri::HTML(html('dragos', 'canonical'))
      pages = Dir.glob(File.join(tmpdir, 'canonical/pages/*.html')).map do |path|
        { 'url' => "https://www.dragos.com/threat-groups/#{File.basename(path, '.html')}",
          'file' => "pages/#{File.basename(path)}" }
      end

      records = importer.send(:parse_actors, document, pages)
      assert_contract self, 'dragos', 'canonical', contract('dragos', records, pages.length)
      assert_equal ['APT29', 'Bronze Butler'], records.map { |row| row['name'] }
    end
  end

  def test_dragos_fetch_classifies_upstream_empty_catalog_in_manifest
    root_html = html('dragos', 'empty')
    importer_class = Class.new(DragosThreatGroupsImporter) do
      define_method(:http_get) { |_url| root_html }
    end

    Dir.mktmpdir('dragos-empty-fetch') do |tmpdir|
      importer = importer_class.new([])
      importer.instance_variable_set(:@options, { output: tmpdir })
      importer.send(:fetch_snapshot)

      manifest = YAML.safe_load(File.read(File.join(tmpdir, 'manifest.yml')))
      assert_equal true, manifest['source_empty']
      refute_empty manifest['empty_reason'].to_s.strip
      assert_equal 'source_empty', SnapshotQualityGate.validate!(tmpdir, source: 'dragos')['classification']
    end
  end

  def test_dragos_fetch_does_not_classify_parser_failure_as_source_empty
    root_html = '<html><body><main><a href="/other">Blocked page</a></main></body></html>'
    importer_class = Class.new(DragosThreatGroupsImporter) do
      define_method(:http_get) { |url| url == DragosThreatGroupsImporter::SOURCE_URL ? root_html : '<html></html>' }
      define_method(:parse_actors) { |_root_doc, _pages| [] }
    end

    Dir.mktmpdir('dragos-parser-failure') do |tmpdir|
      importer = importer_class.new([])
      importer.instance_variable_set(:@options, { output: tmpdir })
      importer.send(:fetch_snapshot)

      manifest = YAML.safe_load(File.read(File.join(tmpdir, 'manifest.yml')))
      refute manifest.key?('source_empty')
      error = assert_raises(SnapshotQualityGate::Rejected) { SnapshotQualityGate.validate!(tmpdir, source: 'dragos') }
      assert_equal 'parser_empty', error.diagnostics['classification']
    end
  end

  def test_timeout_and_http_error_cases_are_retry_or_quarantine_not_empty_success
    %w[timeout http-error].each do |case_name|
      contract_data = expected('dragos', case_name)
      refute_equal 'accepted', contract_data['status']
      refute_nil contract_data['error']
      assert_equal 'Dragos Threat Groups', contract_data.dig('provenance', 'source_name')
    end
  end

  def test_failed_plan_does_not_mutate_generated_data
    Dir.mktmpdir('failed-plan') do |tmpdir|
      generated = File.join(tmpdir, 'generated.json')
      File.write(generated, JSON.generate('actors' => ['before']))
      before = File.binread(generated)

      assert_raises(ArgumentError) { SourceFixtureHarness.fixture('missing-source', 'empty') }

      assert_equal before, File.binread(generated)
    end
  end

  private

  def contract(source, records, detail_pages = nil)
    aliases = records.sum { |record| Array(record['aliases']).length }
    counts = { 'records' => records.length, 'aliases' => aliases }
    counts['detail_pages'] = detail_pages if detail_pages
    { status: records.empty? ? 'quarantine' : 'accepted', counts: counts,
      provenance: { 'source_name' => source == 'unit42' ? Unit42ThreatActorGroupsImporter::SOURCE_NAME : DragosThreatGroupsImporter::SOURCE_NAME } }
  end
end
