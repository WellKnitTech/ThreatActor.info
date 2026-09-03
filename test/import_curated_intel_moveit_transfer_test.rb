# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../scripts/import-curated-intel-moveit-transfer'

class CuratedIntelMoveitTransferTest < Minitest::Test
  def test_plan_report_exposes_validator_counters_for_accepted_event_timeline
    importer = CuratedIntelMoveitTransferImporter.new([])
    records = [{ 'event_type' => 'breach', 'source_url' => 'https://example.test/report' }]

    report = importer.send(:build_report, records)

    assert_equal 1, report[:total_records]
    assert_equal 1, report[:matched]
    assert_equal 0, report[:unmatched]
    assert_equal 0, report[:new_candidates]
  end
end
