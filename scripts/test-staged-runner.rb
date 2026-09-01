#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'
require_relative 'lib/import/staged_runner'

class StagedRunnerTest < Minitest::Test
  Source = Struct.new(:key, :events, :failure, keyword_init: true) do
    def fetch(stage:, attempt:)
      events << [:fetch, attempt]
      raise failure if failure.is_a?(Exception) && attempt == 1
      File.write(File.join(stage, 'snapshot.json'), JSON.generate(source: key))
      { source_key: key, snapshot: File.join(stage, 'snapshot.json') }
    end

    def validate(snapshot:, stage:)
      events << :validate
      raise 'quarantined' if failure == :quarantine
      { snapshot: snapshot, valid: true }
    end

    def plan(snapshot:, stage:)
      events << :plan
      { operations: [{ 'file' => "#{key}.txt", 'content' => key }] }
    end

    def apply(plan:, output:, stage:)
      events << :apply
      raise 'write failed' if failure == :apply
      plan[:operations].each { |op| File.write(File.join(output, op['file']), op['content']) }
    end
  end

  def setup
    @dir = Dir.mktmpdir
    @events = []
  end

  def teardown
    FileUtils.remove_entry(@dir)
  end

  def test_failed_source_fails_closed_without_fallback
    good = Source.new(key: 'good', events: @events)
    bad = Source.new(key: 'bad', events: @events, failure: :quarantine)
    runner = SourceImport::StagedRunner.new(sources: [good, bad], root: @dir)

    assert_raises(RuntimeError) { runner.run }
    assert_equal :failed, runner.states.fetch('bad').status
    refute File.exist?(File.join(@dir, 'output', 'good.txt'))
    assert Dir.glob(File.join(@dir, 'quarantine', 'bad', '*')).any?
  end

  def test_failed_source_uses_verified_fallback_and_reports_degraded_provenance
    good = Source.new(key: 'good', events: @events)
    bad = Source.new(key: 'bad', events: @events, failure: :quarantine)
    fallback = { source_key: 'bad', snapshot: { observed_at: (Time.now.utc - 60).iso8601 },
                 plan: { operations: [{ 'file' => 'bad.txt', 'content' => 'old' }] },
                 observed_at: (Time.now.utc - 60).iso8601, snapshot_id: 'bad-old' }
    bad.define_singleton_method(:last_known_good) { |**_| fallback }
    runner = SourceImport::StagedRunner.new(sources: [good, bad], root: @dir,
                                             max_fallback_age: 3600)

    result = runner.run

    assert_equal :fallback, result.fetch('bad').status
    assert_equal 'bad-old', result.fetch('bad').metadata.fetch('provenance').fetch('snapshot_origin')
    assert_equal 'old', File.read(File.join(@dir, 'output', 'bad.txt'))
    assert_equal :accepted, result.fetch('good').status
  end

  def test_retry_and_rerun_do_not_repeat_successful_source
    flaky_events = []
    stable_events = []
    flaky = Source.new(key: 'flaky', events: flaky_events, failure: RuntimeError.new('timeout'))
    stable = Source.new(key: 'stable', events: stable_events)
    runner = SourceImport::StagedRunner.new(sources: [flaky, stable], root: @dir, retries: 1)

    first = runner.run
    assert_equal :accepted, first.fetch('flaky').status
    assert_equal [[:fetch, 1], [:fetch, 2]], flaky.events.first(2)

    runner.run(source_keys: ['stable'])
    assert_equal 1, stable_events.count { |event| event == [:fetch, 1] }
    assert_equal 2, (flaky_events + stable_events).count(:apply)
  end

  def test_apply_failure_rolls_back_existing_output
    FileUtils.mkdir_p(File.join(@dir, 'output'))
    File.write(File.join(@dir, 'output', 'existing.txt'), 'before')
    source = Source.new(key: 'broken', events: [], failure: :apply)
    runner = SourceImport::StagedRunner.new(sources: [source], root: @dir)

    assert_raises(RuntimeError) { runner.run }
    assert_equal 'before', File.read(File.join(@dir, 'output', 'existing.txt'))
    refute File.exist?(File.join(@dir, 'output', 'broken.txt'))
  end
end
