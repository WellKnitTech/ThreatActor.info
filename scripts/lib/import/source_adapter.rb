# frozen_string_literal: true

require 'digest'
require 'json'
require 'time'

# Shared, dependency-free contract for source importers. Adapters should only
# implement source-specific parsing and policy; orchestration consumes these
# value objects and owns persistence and phase transitions.
module SourceImport
  CONTRACT_VERSION = '1.0'.freeze

  STATUSES = %w[ok source_empty partial rejected quarantined retryable_error fatal_error].freeze
  ERROR_CODES = %w[
    network_timeout network_unavailable http_429 http_5xx http_4xx redirect_rejected
    response_too_large content_type_invalid snapshot_missing_file snapshot_checksum_mismatch
    snapshot_schema_invalid snapshot_partial source_empty parser_empty parser_structure_changed
    parser_malformed_record record_count_below_minimum record_count_above_maximum
    duplicate_rate_exceeded match_unmatched match_ambiguous match_low_confidence match_rejected
    plan_stale plan_invalid apply_preflight_failed apply_write_failed report_failed
  ].freeze
  SEVERITIES = %w[info warning error].freeze

  module_function

  def canonical_json(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, out|
        original_key = value.key?(key) ? key : key.to_sym
        out[key] = canonical_json(value[original_key])
      end
    when Array then value.map { |item| canonical_json(item) }
    when Time then value.utc.iso8601(6)
    when Symbol then value.to_s
    else value
    end
  end

  def checksum(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical_json(value)))
  end

  def deep_freeze(value)
    case value
    when Hash
      value.each { |key, item| deep_freeze(key); deep_freeze(item) }
    when Array
      value.each { |item| deep_freeze(item) }
    end
    value.freeze
  end

  class Value
    def initialize(attributes)
      @attributes = SourceImport.deep_freeze(attributes)
      freeze
    end

    def [](key)
      symbol_key = key.to_sym
      return @attributes[symbol_key] if @attributes.key?(symbol_key)

      @attributes[key.to_s]
    end

    def to_h
      @attributes
    end

    def ==(other)
      other.class == self.class && other.to_h == to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end

    def to_json(*)
      JSON.generate(SourceImport.canonical_json(to_h))
    end
  end

  class Diagnostic < Value
    def initialize(code:, message:, severity: 'error', source_record_id: nil, location: nil, remediation: nil)
      raise ArgumentError, 'diagnostic code is required' if code.to_s.strip.empty?
      raise ArgumentError, "invalid severity: #{severity}" unless SEVERITIES.include?(severity.to_s)

      super(code: code.to_s, known_code: ERROR_CODES.include?(code.to_s), message: message.to_s,
            severity: severity.to_s, source_record_id: source_record_id, location: location,
            remediation: remediation)
    end
  end

  class Result < Value
    def initialize(status:, counts: {}, warnings: [], diagnostics: [], data: nil, metadata: {})
      status = status.to_s
      raise ArgumentError, "invalid status: #{status}" unless STATUSES.include?(status)
      diagnostics = diagnostics.map { |d| d.is_a?(Diagnostic) ? d : Diagnostic.new(**d) }
      super(status: status, counts: counts, warnings: Array(warnings).map(&:to_s),
            diagnostics: diagnostics.map(&:to_h), data: data, metadata: metadata)
    end

    def status = self[:status]
    def diagnostics = self[:diagnostics]
    def success? = %w[ok source_empty partial].include?(status)
  end

  class SnapshotRef < Value
    def initialize(id:, path:, checksum:, retrieved_at:, source_key:, raw_checksum: nil)
      raise ArgumentError, 'snapshot id, path, checksum, and source key are required' if [id, path, checksum, source_key].any? { |v| v.to_s.empty? }
      super(id: id.to_s, path: path.to_s, checksum: checksum.to_s, raw_checksum: raw_checksum&.to_s,
            retrieved_at: Time.parse(retrieved_at.to_s).utc.iso8601(6), source_key: source_key.to_s)
    end
  end

  class SnapshotManifest < Value
    def initialize(source_key:, snapshot_id:, retrieved_at:, source_url:, files: [], counts: {}, checksums: {}, adapter_version: CONTRACT_VERSION, parser_version: '1.0', **extra)
      raise ArgumentError, 'source_key and snapshot_id are required' if source_key.to_s.empty? || snapshot_id.to_s.empty?
      super({ source_key: source_key.to_s, snapshot_id: snapshot_id.to_s, retrieved_at: Time.parse(retrieved_at.to_s).utc.iso8601(6),
              source_url: source_url.to_s, files: Array(files), counts: counts, checksums: checksums,
              adapter_version: adapter_version.to_s, parser_version: parser_version.to_s }.merge(extra))
    end
  end

  class ValidationResult < Result; end
  class ApplyResult < Result; end
  class ReportResult < Result; end

  class Plan < Result
    def initialize(snapshot_checksum:, catalog_revision:, operations: [], resolutions: [], status: 'ok', counts: {}, warnings: [], diagnostics: [], metadata: {})
      operations = Array(operations)
      resolutions = Array(resolutions)
      plan_data = { snapshot_checksum: snapshot_checksum.to_s, catalog_revision: catalog_revision.to_s,
                    operations: operations, resolutions: resolutions }
      super(status: status, counts: counts, warnings: warnings, diagnostics: diagnostics,
            data: plan_data.merge(plan_checksum: SourceImport.checksum(plan_data)), metadata: metadata)
    end

    def plan_checksum = self.dig(:data, :plan_checksum) || self.dig(:data, 'plan_checksum')
    def snapshot_checksum = self.dig(:data, :snapshot_checksum) || self.dig(:data, 'snapshot_checksum')

    def compatible_with?(snapshot_checksum:, catalog_revision:)
      snapshot_checksum.to_s == self.snapshot_checksum && catalog_revision.to_s == self.dig(:data, :catalog_revision)
    end

    def dig(*keys)
      keys.reduce(to_h) { |value, key| value.is_a?(Hash) ? (value[key] || value[key.to_s]) : nil }
    end
  end

  class RunReport < Value
    def initialize(run_id:, source_key:, phase:, result:, duration_ms: 0, retry_decision: nil, quarantine_ref: nil)
      raise ArgumentError, 'run_id and source_key are required' if run_id.to_s.empty? || source_key.to_s.empty?
      result = result.is_a?(Result) ? result : Result.new(**result)
      super(run_id: run_id.to_s, source_key: source_key.to_s, phase: phase.to_s,
            status: result[:status], duration_ms: duration_ms.to_f, counts: result[:counts],
            warnings: result[:warnings], diagnostics: result[:diagnostics], data: result[:data],
            metadata: result[:metadata], retry_decision: retry_decision, quarantine_ref: quarantine_ref,
            schema_version: CONTRACT_VERSION)
    end
  end

  module SourceAdapter
    REQUIRED_PHASES = %i[fetch validate_snapshot plan apply report].freeze

    def source_key
      raise NotImplementedError, 'adapter must define source_key'
    end

    def metadata
      {}
    end

    REQUIRED_PHASES.each do |phase|
      define_method(phase) do |*_args|
        raise NotImplementedError, "adapter must implement #{phase}"
      end
    end
  end

  # Allows existing fetch/plan/import scripts to enter the contract without
  # changing their CLI. New code should implement SourceAdapter directly.
  class LegacyAdapter
    include SourceAdapter

    def initialize(source_key:, legacy:, metadata: {})
      @source_key = source_key.to_s
      @legacy = legacy
      @metadata = metadata
    end

    attr_reader :source_key
    attr_reader :metadata

    def fetch(context = {}) = Result.new(status: 'ok', data: @legacy.fetch(context))
    def validate_snapshot(snapshot, context = {}) = Result.new(status: 'ok', data: snapshot)
    def plan(snapshot, catalog, context = {}) = Result.new(status: 'ok', data: @legacy.plan(snapshot, catalog, context))
    def apply(plan, writer, context = {}) = Result.new(status: 'ok', data: @legacy.apply(plan, writer, context))
    def report(results, sink = nil)
      payload = results.map { |result| result.respond_to?(:to_h) ? result.to_h : result }
      sink.call(payload) if sink.respond_to?(:call)
      Result.new(status: 'ok', data: payload)
    end
  end
end
