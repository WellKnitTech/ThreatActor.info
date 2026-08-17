# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'tmpdir'
require 'yaml'

module SourceFixtureHarness
  ROOT = File.expand_path('../..', __dir__)
  FIXTURE_ROOT = File.join(ROOT, 'test', 'fixtures', 'source_imports')

  module_function

  def fixture(source, case_name)
    path = File.join(FIXTURE_ROOT, source, case_name)
    raise ArgumentError, "unknown fixture: #{source}/#{case_name}" unless Dir.exist?(path)

    path
  end

  def html(source, case_name, file = nil)
    root = fixture(source, case_name)
    file ||= source == 'dragos' ? 'index.html' : 'page.html'
    File.read(File.join(root, file))
  end

  def expected(source, case_name)
    JSON.parse(File.read(File.join(fixture(source, case_name), 'expected.json')))
  end

  def snapshot(source, case_name)
    root = fixture(source, case_name)
    Dir.glob(File.join(root, '**', '*'), File::FNM_DOTMATCH).select { |path| File.file?(path) }
        .reject { |path| path.end_with?('expected.json') }
        .sort.to_h { |path| [path.delete_prefix("#{root}/"), File.binread(path)] }
  end

  def copy_snapshot(source, case_name, destination)
    FileUtils.cp_r(fixture(source, case_name), destination)
  end

  def assert_contract(test_case, source, case_name, actual)
    expected_contract = expected(source, case_name)
    test_case.assert_equal expected_contract['status'], actual.fetch(:status)
    expected_contract.fetch('counts', {}).each do |key, value|
      test_case.assert_equal value, actual.fetch(:counts).fetch(key), "#{source}/#{case_name} count #{key}"
    end
    expected_contract.fetch('provenance', {}).each do |key, value|
      test_case.assert_equal value, actual.fetch(:provenance).fetch(key), "#{source}/#{case_name} provenance #{key}"
    end
  end
end
