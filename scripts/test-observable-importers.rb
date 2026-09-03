#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require_relative 'actor_store'
require_relative 'import-malwarebazaar'
require_relative 'import-urlhaus'

class ObservableImportersTest < Minitest::Test
  ROOT = File.expand_path('../test/fixtures/source_imports', __dir__)

  def test_malwarebazaar_quarantines_invalid_and_deduplicates
    assert_report('malwarebazaar', File.join(ROOT, 'malwarebazaar', 'partial.json'), 1, 1)
  end

  def test_urlhaus_quarantines_invalid_and_deduplicates
    assert_report('urlhaus', File.join(ROOT, 'urlhaus', 'partial.json'), 1, 1)
  end

  def test_malformed_snapshots_fail_closed
    [
      [MalwareBazaarImporter, File.join(ROOT, 'malwarebazaar', 'malformed.payload')],
      [UrlhausImporter, File.join(ROOT, 'urlhaus', 'malformed.payload')]
    ].each do |klass, path|
      error = assert_raises(RuntimeError) { klass.new.send(:process_snapshot, path, report_path: nil) }
      assert_match(/malformed/, error.message)
    end
  end

  private

  def assert_report(source, snapshot, expected_records, expected_quarantined)
    Dir.mktmpdir do |dir|
      report = File.join(dir, 'report.json')
      klass = source == 'urlhaus' ? UrlhausImporter : MalwareBazaarImporter
      klass.new.send(:process_snapshot, snapshot, report_path: report)
      payload = JSON.parse(File.read(report))
      assert_equal expected_records, payload['records']
      assert_equal expected_quarantined, payload['quarantined']
    end
  end
end
