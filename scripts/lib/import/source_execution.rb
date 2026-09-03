# frozen_string_literal: true

require 'set'

# Bounded per-source process execution for the canonical import runner.
# Job/source deadlines, process-group cancellation, and retry classification
# live here so CI cannot replay the full source universe after one failure.
module SourceImport
  module SourceExecution
    DEFAULT_JOB_DEADLINE = 2700
    DEFAULT_SOURCE_DEADLINE = 600
    DEFAULT_MAX_ATTEMPTS = 3
    DEFAULT_SLEEP_CAP = 30

    class DeadlineExceeded < StandardError; end
    class JobDeadlineExceeded < DeadlineExceeded; end
    class Cancelled < StandardError; end
    class CommandFailed < StandardError
      attr_reader :exit_code, :stdout, :stderr

      def initialize(message, exit_code: nil, stdout: '', stderr: '')
        super(message)
        @exit_code = exit_code
        @stdout = stdout.to_s
        @stderr = stderr.to_s
      end
    end
    class RetryExhausted < StandardError
      attr_reader :cause_error, :attempts, :status

      def initialize(cause_error, attempts:, status:)
        @cause_error = cause_error
        @attempts = attempts
        @status = status
        super("#{status} after #{attempts} attempt(s): #{cause_error.message}")
      end
    end

    ProcessResult = Struct.new(:exit_code, :stdout, :stderr, :timed_out, :cancelled, keyword_init: true) do
      def success?
        !timed_out && !cancelled && exit_code.to_i.zero?
      end
    end

    Classification = Struct.new(:status, :retryable, :retry_after, keyword_init: true)

    module_function

    def reset!
      @cancelled = false
      @deadline_at = nil
      @clock = nil
      @active_pgids = Set.new
      @mutex = Mutex.new
    end

    def cancelled?
      @cancelled == true || job_expired?
    end

    def cancel!
      @cancelled = true
      kill_active
    end

    def arm_job_deadline!(seconds, clock: nil)
      @clock = clock
      @deadline_at = now + Float(seconds)
    end

    def remaining_job_seconds
      return Float::INFINITY unless @deadline_at

      [@deadline_at - now, 0.0].max
    end

    def job_expired?
      @deadline_at && remaining_job_seconds <= 0
    end

    def raise_if_cancelled!
      raise Cancelled, 'import cancelled' if @cancelled
      raise JobDeadlineExceeded, 'job deadline exceeded' if job_expired?
    end

    def install_signal_traps!
      %w[INT TERM].each do |name|
        Signal.trap(name) { cancel! }
      end
    end

    def classify(message)
      text = "#{message}\n"
      retry_after = parse_retry_after(text)
      if text.match?(/unauthoriz|unauthenticat|\bhttp 401\b|\bhttp 403\b|authentication/i)
        return Classification.new(status: 'auth_failure', retryable: false)
      end
      if text.match?(/licen[cs]e|licensing/i)
        return Classification.new(status: 'licensing_failure', retryable: false)
      end
      if text.match?(/schema/i)
        return Classification.new(status: 'schema_failure', retryable: false)
      end
      if text.match?(/validat|plan anomal|quality gate|snapshot quarantined/i)
        return Classification.new(status: 'validation_failure', retryable: false)
      end
      if text.match?(/http 429|rate.?limit|retry-after/i)
        return Classification.new(status: 'rate_limited', retryable: true, retry_after: retry_after)
      end
      if text.match?(/job deadline exceeded/i)
        return Classification.new(status: 'cancelled', retryable: false)
      end
      if text.match?(/timeout|deadline/i)
        return Classification.new(status: 'timeout', retryable: true)
      end
      if text.match?(/cancel/i)
        return Classification.new(status: 'cancelled', retryable: false)
      end
      if text.match?(/\bhttp 5\d\d\b/i)
        return Classification.new(status: 'http_5xx', retryable: true)
      end
      if text.match?(/connection (refused|reset)|network|unavailable|name or service not known/i)
        return Classification.new(status: 'network', retryable: true)
      end
      if text.match?(/\bhttp 4\d\d\b/i)
        return Classification.new(status: 'http_4xx', retryable: false)
      end

      Classification.new(status: 'failed', retryable: false)
    end

    def parse_retry_after(text)
      match = text.match(/Retry-After\s*[:=]\s*(\d+)/i)
      match && match[1].to_i
    end

    def retry_delay(classification, attempt, sleep_cap:)
      cap = [Integer(sleep_cap), 0].max
      base = classification.retry_after || (2**(attempt - 1))
      [base, cap].min
    end

    def retry(max_attempts:, sleeper: Kernel.method(:sleep), sleep_cap: env_int('IMPORT_RETRY_SLEEP_CAP_SECONDS', DEFAULT_SLEEP_CAP))
      attempts = 0
      last_error = nil
      last_status = 'failed'
      Integer(max_attempts).times do
        raise_if_cancelled!
        attempts += 1
        begin
          return yield(attempts)
        rescue Cancelled, JobDeadlineExceeded
          raise
        rescue DeadlineExceeded, CommandFailed, StandardError => error
          last_error = error
          info = classify(error.message)
          last_status = info.status
          raise error unless info.retryable
          break unless attempts < Integer(max_attempts)

          delay = retry_delay(info, attempts, sleep_cap: sleep_cap)
          sleeper.call(delay) if delay.positive?
        end
      end
      raise RetryExhausted.new(last_error, attempts: attempts, status: last_status)
    end

    def run_process(command, timeout:, env: nil)
      raise_if_cancelled!
      timeout = Float(timeout)
      raise DeadlineExceeded, "deadline exceeded before starting: #{Array(command).join(' ')}" if timeout <= 0

      stdout_r, stdout_w = IO.pipe
      stderr_r, stderr_w = IO.pipe
      pid = nil
      pgid = nil
      begin
        spawn_args = [*Array(command), { out: stdout_w, err: stderr_w, pgroup: true }]
        pid = env ? Process.spawn(env, *spawn_args) : Process.spawn(*spawn_args)
        stdout_w.close
        stderr_w.close
        pgid = Process.getpgid(pid)
        register(pgid)
        exit_code = wait_pid(pid, timeout)
        stdout = stdout_r.read
        stderr = stderr_r.read
        ProcessResult.new(exit_code: exit_code, stdout: stdout, stderr: stderr,
                          timed_out: false, cancelled: false)
      rescue Cancelled, JobDeadlineExceeded
        kill_group(pgid) if pgid
        reap(pid) if pid
        raise
      rescue DeadlineExceeded
        kill_group(pgid) if pgid
        reap(pid) if pid
        raise DeadlineExceeded, "deadline exceeded after #{timeout}s: #{Array(command).join(' ')}"
      ensure
        unregister(pgid) if pgid
        [stdout_w, stderr_w, stdout_r, stderr_r].each { |io| io.close unless io.closed? }
      end
    end

    def command_error(result, command)
      detail = [result.stderr, result.stdout].map { |part| part.to_s.strip }.reject(&:empty?).first
      message = "Command failed with exit #{result.exit_code}: #{Array(command).join(' ')}"
      message = "#{message}: #{detail}" if detail
      CommandFailed.new(message, exit_code: result.exit_code, stdout: result.stdout, stderr: result.stderr)
    end

    def env_int(name, default)
      Integer(ENV.fetch(name, default))
    end

    def source_deadline_seconds
      env_int('IMPORT_SOURCE_DEADLINE_SECONDS', DEFAULT_SOURCE_DEADLINE)
    end

    def max_attempts
      env_int('IMPORT_SOURCE_MAX_ATTEMPTS', DEFAULT_MAX_ATTEMPTS)
    end

    def command_timeout(limit = source_deadline_seconds)
      [Float(limit), remaining_job_seconds].min
    end

    def now
      (@clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }).call
    end

    def wait_pid(pid, timeout)
      started = now
      loop do
        raise_if_cancelled!
        raise DeadlineExceeded if (now - started) >= timeout

        waited_pid, status = Process.wait2(pid, Process::WNOHANG)
        return status.exitstatus if waited_pid

        sleep(0.05)
      end
    end

    def register(pgid)
      mutex.synchronize { active_pgids << pgid }
    end

    def unregister(pgid)
      mutex.synchronize { active_pgids.delete(pgid) }
    end

    def kill_active
      mutex.synchronize { active_pgids.dup }.each { |pgid| kill_group(pgid) }
    end

    def kill_group(pgid)
      Process.kill('TERM', -pgid)
      20.times do
        begin
          Process.kill(0, -pgid)
        rescue Errno::ESRCH
          return
        end
        sleep(0.05)
      end
      Process.kill('KILL', -pgid)
    rescue Errno::ESRCH, Errno::EPERM
      nil
    end

    def reap(pid)
      Process.wait(pid)
    rescue Errno::ECHILD
      nil
    end

    def mutex
      @mutex ||= Mutex.new
    end

    def active_pgids
      @active_pgids ||= Set.new
    end
  end
end

SourceImport::SourceExecution.reset!
