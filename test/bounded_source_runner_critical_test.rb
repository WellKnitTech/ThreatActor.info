# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../scripts/lib/import/bounded_source_runner'

class BoundedSourceRunnerCriticalTest < Minitest::Test
  Item = Struct.new(:key, :critical, keyword_init: true) do
    def critical?
      critical == true
    end
  end

  def test_non_critical_failure_does_not_skip_remaining_sources
    items = [
      Item.new(key: 'enrichment', critical: false),
      Item.new(key: 'mitre-attack', critical: true)
    ]
    started = []
    results = SourceImport::BoundedSourceRunner.new(
      items, workers: 1, fail_fast: ->(item) { item.critical? }
    ).run do |item|
      started << item.key
      raise 'boom' if item.key == 'enrichment'

      :ok
    end

    assert_equal %w[enrichment mitre-attack], started
    assert results[0].error
    assert_equal :ok, results[1].value
    refute results[1].skipped
  end

  def test_critical_failure_skips_remaining_sources
    items = [
      Item.new(key: 'mitre-attack', critical: true),
      Item.new(key: 'enrichment', critical: false)
    ]
    started = []
    results = SourceImport::BoundedSourceRunner.new(
      items, workers: 1, fail_fast: ->(item) { item.critical? }
    ).run do |item|
      started << item.key
      raise 'boom' if item.key == 'mitre-attack'

      :ok
    end

    assert_equal %w[mitre-attack], started
    assert results[0].error
    assert results[1].skipped
  end
end
