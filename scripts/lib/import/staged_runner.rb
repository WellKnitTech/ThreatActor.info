# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'securerandom'

module SourceImport
  # Coordinates source work as fetch -> validate -> plan -> (all accepted) apply.
  # Source adapters receive only their private staging directory during planning.
  class StagedRunner
    SourceState = Struct.new(:status, :snapshot, :plan, :error, keyword_init: true) do
      def to_h
        { 'status' => status.to_s, 'snapshot' => snapshot, 'plan' => plan, 'error' => error }
      end
    end

    Result = Struct.new(:status, :snapshot, :plan, :error, keyword_init: true)

    def initialize(sources:, root:, output: File.join(root, 'output'), retries: 0, regenerate: nil)
      @sources = sources.each_with_object({}) { |source, memo| memo[source.key.to_s] = source }
      @root = root
      @output = output
      @retries = Integer(retries)
      @regenerate = regenerate
      @states = {}
      FileUtils.mkdir_p(@root)
    end

    attr_reader :states

    def run(source_keys: nil)
      keys = source_keys ? source_keys.map(&:to_s) : @sources.keys.sort
      unknown = keys - @sources.keys
      raise ArgumentError, "unknown source(s): #{unknown.join(', ')}" unless unknown.empty?

      changed = keys.reject { |key| accepted?(@states[key]) }
      changed.each { |key| stage_source(key) }
      accepted_changed = changed.select { |key| accepted?(@states[key]) }
      return results if accepted_changed.empty?

      apply_accepted(accepted_changed)
      @regenerate&.call
      results
    end

    private

    def accepted?(state)
      state && state.status == :accepted
    end

    def stage_source(key)
      source = @sources.fetch(key)
      stage = File.join(@root, 'staging', key)
      FileUtils.rm_rf(stage)
      FileUtils.mkdir_p(stage)
      snapshot = nil
      begin
        attempts = 0
        begin
          attempts += 1
          snapshot = source.fetch(stage: stage, attempt: attempts)
        rescue StandardError => error
          retry if attempts <= @retries
          raise error
        end
        source.validate(snapshot: snapshot, stage: stage)
        plan = source.plan(snapshot: snapshot, stage: stage)
        @states[key] = SourceState.new(status: :accepted, snapshot: snapshot, plan: plan)
      rescue StandardError => error
        @states[key] = SourceState.new(status: :quarantined, snapshot: snapshot,
                                       error: error.message)
      end
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
                                    stage: File.join(@root, 'staging', key))
        end
        FileUtils.rm_rf(backup)
        FileUtils.mv(@output, backup) if File.exist?(@output)
        FileUtils.mv(candidate, @output)
        FileUtils.rm_rf(backup)
      rescue StandardError
        FileUtils.rm_rf(@output) unless File.exist?(@output)
        FileUtils.mv(backup, @output) if defined?(backup) && File.exist?(backup)
        raise
      ensure
        FileUtils.rm_rf(transaction)
      end
    end

    def results
      @states.transform_values do |state|
        Result.new(status: state.status, snapshot: state.snapshot,
                   plan: state.plan, error: state.error)
      end
    end
  end
end
