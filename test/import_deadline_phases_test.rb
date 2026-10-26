# frozen_string_literal: true

require 'minitest/autorun'
require 'rbconfig'
require_relative '../scripts/lib/import/source_execution'

# Regression: per-source deadlines must be fresh for each phase. Caching one
# absolute deadline across fetch/plan and import made early sources expire
# before import started once the full source universe exceeded 600s wall-clock
# (Weekly Threat Data failures from 2026-09-06 onward).
class ImportDeadlinePhasesTest < Minitest::Test
  def setup
    SourceImport::SourceExecution.reset!
    @previous = ENV['IMPORT_SOURCE_DEADLINE_SECONDS']
    ENV['IMPORT_SOURCE_DEADLINE_SECONDS'] = '1'
  end

  def teardown
    SourceImport::SourceExecution.reset!
    if @previous
      ENV['IMPORT_SOURCE_DEADLINE_SECONDS'] = @previous
    else
      ENV.delete('IMPORT_SOURCE_DEADLINE_SECONDS')
    end
  end

  def with_source_deadline
    SourceImport::SourceExecution.with_source_deadline { yield }
  end

  def test_fresh_deadline_allows_later_phase_after_prior_phase_budget_expires
    with_source_deadline do
      SourceImport::SourceExecution.raise_if_cancelled!
    end

    sleep 1.05

    with_source_deadline do
      SourceImport::SourceExecution.raise_if_cancelled!
    end
  end

  def test_cached_deadline_across_phases_would_fail_import
    # Document the broken pattern removed from import-automated-sources.rb.
    cached = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.2
    SourceImport::SourceExecution.with_source_deadline(deadline_at: cached) do
      SourceImport::SourceExecution.raise_if_cancelled!
    end
    sleep 0.25
    error = assert_raises(SourceImport::SourceExecution::SourceDeadlineExceeded) do
      SourceImport::SourceExecution.with_source_deadline(deadline_at: cached) do
        SourceImport::SourceExecution.raise_if_cancelled!
      end
    end
    assert_match(/source deadline exceeded/, error.message)
  end
end
