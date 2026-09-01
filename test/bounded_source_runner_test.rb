# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require_relative '../scripts/lib/import/bounded_source_runner'

class BoundedSourceRunnerTest < Minitest::Test
  def test_runs_independent_jobs_in_parallel_and_returns_input_order
    started = Queue.new
    results = SourceImport::BoundedSourceRunner.new(%w[a b], workers: 2).run do |item|
      started << item
      sleep 0.15
      item.upcase
    end

    assert_equal %w[a b], results.map(&:item)
    assert_equal %w[A B], results.map(&:value)
    assert_equal %w[a b], 2.times.map { started.pop }.sort
  end

  def test_fail_fast_skips_queued_jobs_and_preserves_error
    items = %w[bad queued]
    results = SourceImport::BoundedSourceRunner.new(items, workers: 1).run do |item|
      raise 'boom' if item == 'bad'
      flunk 'queued work should be cancelled'
    end

    assert_equal 'boom', results[0].error.message
    assert results[1].skipped
  end

  def test_continue_on_error_runs_all_jobs
    results = SourceImport::BoundedSourceRunner.new(%w[bad good], workers: 2, fail_fast: false).run do |item|
      raise 'boom' if item == 'bad'
      :ok
    end

    assert_equal 'boom', results[0].error.message
    assert_equal :ok, results[1].value
  end

  def test_rejects_unbounded_worker_limit
    assert_raises(ArgumentError) { SourceImport::BoundedSourceRunner.new([], workers: 0) }
  end
end
