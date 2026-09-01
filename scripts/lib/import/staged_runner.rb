# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'
require 'time'

module SourceImport
  # Runs independent sources in quarantine, then commits the accepted source set
  # with one atomic output swap. Fallback lookup is deliberately adapter-owned:
  # the runner never guesses from mtimes or generated output.
  class StagedRunner
    SourceState = Struct.new(
      :status, :snapshot, :plan, :error, :failure_stage, :attempted_at,
      :observed_at, :age_seconds, :provenance, :applied, :quarantine, :stage,
      keyword_init: true
    ) do
      def to_h
        {
          'status' => status.to_s, 'snapshot' => snapshot, 'plan' => plan,
          'error' => error, 'failure_stage' => failure_stage&.to_s,
          'attempted_at' => attempted_at, 'observed_at' => observed_at,
          'age_seconds' => age_seconds, 'provenance' => provenance,
          'applied' => applied == true, 'quarantine' => quarantine
        }
      end
    end

    Result = Struct.new(:status, :snapshot, :plan, :error, :metadata, keyword_init: true)

    def initialize(sources:, root:, output: File.join(root, 'output'), retries: 0,
                   regenerate: nil, evaluated_at: Time.now.utc, max_fallback_age: nil,
                   report_path: nil)
      @sources = sources.each_with_object({}) { |source, memo| memo[source.key.to_s] = source }
      @root, @output, @retries, @regenerate = root, output, Integer(retries), regenerate
      @evaluated_at, @max_fallback_age, @report_path = evaluated_at.utc, max_fallback_age, report_path
      @states = {}
      FileUtils.mkdir_p(@root)
    end

    attr_reader :states

    def run(source_keys: nil)
      keys = source_keys ? source_keys.map(&:to_s) : @sources.keys.sort_by { |key| @sources.fetch(key).respond_to?(:priority) ? @sources.fetch(key).priority : key }
      unknown = keys - @sources.keys
      raise ArgumentError, "unknown source(s): #{unknown.join(', ')}" unless unknown.empty?

      changed = keys.reject { |key| accepted?(@states[key]) }
      changed.each { |key| stage_source(key) }
      failed = @states.values.select { |state| state.status == :failed }
      write_report
      raise RuntimeError, "import run failed closed: #{failed.map(&:error).compact.join('; ')}" unless failed.empty?

      accepted = changed.select { |key| %i[accepted fallback].include?(@states[key]&.status) }
      apply_accepted(accepted) unless accepted.empty?
      accepted.each { |key| @states.fetch(key).applied = true }
      @regenerate&.call unless accepted.empty?
      write_report
      results
    end

    private

    def snapshot_key(state)
      @states.key(state)
    end

    def accepted?(state)
      state && %i[accepted fallback].include?(state.status)
    end

    def stage_source(key)
      source = @sources.fetch(key)
      stage = File.join(@root, 'staging', key)
      FileUtils.rm_rf(stage)
      FileUtils.mkdir_p(stage)
      attempted_at = @evaluated_at.iso8601(6)
      snapshot = nil
      failure_stage = :fetch
      begin
        attempts = 0
        begin
          attempts += 1
          snapshot = source.fetch(stage: stage, attempt: attempts)
        rescue StandardError => error
          retry if attempts <= @retries
          raise error
        end
        failure_stage = :validate
        source.validate(snapshot: snapshot, stage: stage)
        failure_stage = :plan
        plan = source.plan(snapshot: snapshot, stage: stage)
        @states[key] = SourceState.new(status: :accepted, snapshot: snapshot, plan: plan, stage: stage,
                                       attempted_at: attempted_at, observed_at: observed_at(snapshot),
                                       provenance: { 'snapshot_origin' => 'current_attempt' }, applied: false)
      rescue StandardError => error
        quarantine = quarantine_stage(stage, key)
        fallback = select_fallback(source, stage, error, failure_stage)
        if fallback
          @states[key] = fallback_state(fallback, error, failure_stage, attempted_at, quarantine)
        else
          @states[key] = SourceState.new(status: :failed, snapshot: snapshot, error: redacted(error.message),
                                         failure_stage: failure_stage, attempted_at: attempted_at,
                                         provenance: { 'snapshot_origin' => 'failed_attempt' }, applied: false,
                                         quarantine: quarantine)
        end
      end
    end

    def select_fallback(source, stage, error, failure_stage)
      return unless source.respond_to?(:last_known_good)
      limit = source.respond_to?(:max_fallback_age) ? source.max_fallback_age : @max_fallback_age
      return if limit.nil?
      candidate = source.last_known_good(stage: stage, evaluated_at: @evaluated_at,
                                         max_fallback_age: limit, failure: error,
                                         failure_stage: failure_stage)
      return if candidate.nil?
      candidate = { snapshot: candidate } unless candidate.is_a?(Hash)
      observed = candidate[:observed_at] || candidate['observed_at'] || observed_at(candidate[:snapshot] || candidate['snapshot'])
      return unless observed
      age = @evaluated_at - Time.parse(observed.to_s).utc
      return if age.negative? || age > Float(limit)
      candidate
    rescue StandardError
      nil
    end

    def fallback_state(candidate, error, failure_stage, attempted_at, quarantine)
      snapshot = candidate[:snapshot] || candidate['snapshot']
      plan = candidate[:plan] || candidate['plan']
      raise 'fallback candidate has no reusable plan' unless plan
      observed = candidate[:observed_at] || candidate['observed_at'] || observed_at(snapshot)
      SourceState.new(status: :fallback, snapshot: snapshot, plan: plan,
                      stage: candidate[:stage] || candidate['stage'] || (snapshot.is_a?(Hash) ? snapshot[:path] || snapshot['path'] : snapshot),
                      error: redacted(error.message), failure_stage: failure_stage,
                      attempted_at: attempted_at, observed_at: observed.to_s,
                      age_seconds: (@evaluated_at - Time.parse(observed.to_s).utc).to_i,
                      provenance: { 'snapshot_origin' => candidate[:snapshot_id] || candidate['snapshot_id'] || snapshot,
                                    'fallback_reason' => redacted(error.message) }, applied: false,
                      quarantine: quarantine)
    end

    def quarantine_stage(stage, key)
      return unless Dir.exist?(stage) && !Dir.empty?(stage)
      destination = File.join(@root, 'quarantine', key, SecureRandom.hex(6))
      FileUtils.mkdir_p(File.dirname(destination))
      FileUtils.mv(stage, destination)
      destination
    end

    def observed_at(snapshot)
      return unless snapshot.is_a?(Hash)
      snapshot[:observed_at] || snapshot['observed_at'] || snapshot[:retrieved_at] || snapshot['retrieved_at']
    end

    def redacted(message)
      message.to_s.gsub(/authorization\s*:\s*\S+/i, 'authorization: [REDACTED]').gsub(/(token|secret|password)\s*[:=]\s*\S+/i, '\\1=[REDACTED]')[0, 500]
    end

    def apply_accepted(keys)
      transaction = File.join(@root, '.apply', SecureRandom.hex(8))
      FileUtils.mkdir_p(transaction)
      FileUtils.cp_r(@output, transaction) if File.directory?(@output)
      candidate = File.join(transaction, 'output')
      backup = "#{@output}.rollback"
      FileUtils.mkdir_p(candidate)
      begin
        keys.each do |key|
          state = @states.fetch(key)
          @sources.fetch(key).apply(plan: state.plan, output: candidate,
                                    stage: state.stage || File.join(@root, 'staging', key))
        end
        FileUtils.rm_rf(backup)
        FileUtils.mv(@output, backup) if File.exist?(@output)
        FileUtils.mv(candidate, @output)
        FileUtils.rm_rf(backup)
      rescue StandardError
        FileUtils.rm_rf(@output) unless File.exist?(@output)
        FileUtils.mv(backup, @output) if File.exist?(backup)
        raise
      ensure
        FileUtils.rm_rf(transaction)
      end
    end

    def write_report
      return unless @report_path
      FileUtils.mkdir_p(File.dirname(@report_path))
      File.write(@report_path, JSON.pretty_generate('evaluated_at' => @evaluated_at.iso8601(6), 'sources' => @states.transform_values(&:to_h)) + "\n")
    end

    def results
      @states.transform_values { |state| Result.new(status: state.status, snapshot: state.snapshot,
                                                     plan: state.plan, error: state.error,
                                                     metadata: state.to_h) }
    end
  end
end
