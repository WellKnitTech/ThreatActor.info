# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'rbconfig'
require 'tmpdir'
require_relative '../scripts/lib/import/source_execution'

class SourceExecutionTest < Minitest::Test
  FIXTURES = File.expand_path('fixtures/source_execution', __dir__)

  def setup
    SourceImport::SourceExecution.reset!
  end

  def teardown
    SourceImport::SourceExecution.reset!
  end

  def ruby_fixture(name, *args)
    [RbConfig.ruby, File.join(FIXTURES, name), *args]
  end

  def run_fixture(name, *args, timeout:)
    SourceImport::SourceExecution.run_process(ruby_fixture(name, *args), timeout: timeout)
  end

  def retrying(max_attempts:, sleeper: ->(_delay) {}, sleep_cap: 30)
    SourceImport::SourceExecution.retry(max_attempts: max_attempts, sleeper: sleeper, sleep_cap: sleep_cap) do |attempt|
      yield attempt
    end
  end

  def test_timeout_kills_child_process
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = assert_raises(SourceImport::SourceExecution::DeadlineExceeded) do
      run_fixture('hang.rb', timeout: 0.3)
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_match(/deadline exceeded/, error.message)
    assert elapsed < 2.0, "child was not killed promptly (#{elapsed}s)"
  end

  def test_timeout_kills_child_that_ignores_term
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_raises(SourceImport::SourceExecution::DeadlineExceeded) do
      run_fixture('ignore_term.rb', timeout: 0.3)
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert elapsed < 3.0, "KILL was not used after TERM was ignored (#{elapsed}s)"
  end

  def test_cancellation_kills_running_child
    thread = nil
    error = nil
    thread = Thread.new do
      error = begin
        run_fixture('hang.rb', timeout: 5)
        nil
      rescue StandardError => raised
        raised
      end
    end
    sleep 0.15
    SourceImport::SourceExecution.cancel!
    thread.join

    assert_instance_of SourceImport::SourceExecution::Cancelled, error
  end

  def test_429_retries_same_source_only_and_honors_capped_retry_after
    delays = []
    counts = Hash.new(0)
    records = {}

    %w[ok rate-limited].each do |key|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      attempts = 0
      status = 'ok'
      begin
        retrying(max_attempts: 3, sleeper: ->(delay) { delays << delay }, sleep_cap: 5) do |attempt|
          attempts = attempt
          counts[key] += 1
          next :ok if key == 'ok'

          result = run_fixture('http_429.rb', timeout: 2)
          raise SourceImport::SourceExecution.command_error(result, ['429']) unless result.success?
        end
      rescue SourceImport::SourceExecution::RetryExhausted => error
        status = error.status
      end
      records[key] = {
        'elapsed_ms' => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(1),
        'attempts' => attempts,
        'request_count' => counts[key],
        'status' => status
      }
    end

    assert_equal 1, counts['ok']
    assert_equal 3, counts['rate-limited']
    assert_equal 'ok', records['ok']['status']
    assert_equal 'rate_limited', records['rate-limited']['status']
    assert_equal [5, 5], delays
    assert records['ok']['elapsed_ms'] >= 0
    assert records['rate-limited']['request_count'] == 3
  end

  def test_retry_exhaustion_records_terminal_status
    attempts = 0
    error = assert_raises(SourceImport::SourceExecution::RetryExhausted) do
      retrying(max_attempts: 3) do |attempt|
        attempts = attempt
        result = run_fixture('http_503.rb', timeout: 2)
        raise SourceImport::SourceExecution.command_error(result, ['503']) unless result.success?
      end
    end

    assert_equal 3, attempts
    assert_equal 3, error.attempts
    assert_equal 'http_5xx', error.status
  end

  def test_auth_licensing_schema_and_validation_are_not_retried
    {
      'http_401.rb' => 'auth_failure',
      'licensing.rb' => 'licensing_failure',
      'schema.rb' => 'schema_failure',
      'validation.rb' => 'validation_failure'
    }.each do |fixture, status|
      attempts = 0
      error = assert_raises(SourceImport::SourceExecution::CommandFailed) do
        retrying(max_attempts: 3) do |attempt|
          attempts = attempt
          result = run_fixture(fixture, timeout: 2)
          raise SourceImport::SourceExecution.command_error(result, [fixture]) unless result.success?
        end
      end
      assert_equal 1, attempts, fixture
      assert_equal status, SourceImport::SourceExecution.classify(error.message).status
      refute SourceImport::SourceExecution.classify(error.message).retryable, fixture
    end
  end

  def test_partial_completion_does_not_rerun_successful_sources
    Dir.mktmpdir do |dir|
      state = File.join(dir, 'flaky')
      counts = Hash.new(0)
      statuses = {}

      %w[alpha flaky omega].each do |key|
        begin
          retrying(max_attempts: 3) do
            counts[key] += 1
            case key
            when 'alpha', 'omega'
              result = run_fixture('ok.rb', timeout: 2)
            else
              result = run_fixture('flaky.rb', state, timeout: 2)
            end
            raise SourceImport::SourceExecution.command_error(result, [key]) unless result.success?
          end
          statuses[key] = 'ok'
        rescue StandardError => error
          statuses[key] = SourceImport::SourceExecution.classify(error.message).status
        end
      end

      assert_equal({ 'alpha' => 1, 'flaky' => 2, 'omega' => 1 }, counts)
      assert_equal({ 'alpha' => 'ok', 'flaky' => 'ok', 'omega' => 'ok' }, statuses)
    end
  end

  def test_no_duplicate_full_run_retries
    counts = Hash.new(0)
    universe_runs = 0

    universe_runs += 1
    %w[mitre malpedia].each do |key|
      retrying(max_attempts: 3) do
        counts[key] += 1
        next if key == 'mitre'

        result = run_fixture('http_429.rb', timeout: 2)
        raise SourceImport::SourceExecution.command_error(result, [key]) unless result.success?
      end
    rescue SourceImport::SourceExecution::RetryExhausted
      nil
    end

    assert_equal 1, universe_runs
    assert_equal 1, counts['mitre']
    assert_equal 3, counts['malpedia']
  end

  def test_job_deadline_prevents_starting_later_sources
    SourceImport::SourceExecution.arm_job_deadline!(0.05)
    sleep 0.07
    started = []

    %w[one two].each do |key|
      SourceImport::SourceExecution.retry(max_attempts: 2, sleeper: ->(_) {}) do
        started << key
        run_fixture('ok.rb', timeout: 2)
      end
    rescue SourceImport::SourceExecution::DeadlineExceeded, SourceImport::SourceExecution::Cancelled
      nil
    end

    assert_empty started
  end
end
