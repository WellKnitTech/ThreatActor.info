#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'digest'
require 'minitest/autorun'
require 'tmpdir'
require 'time'
require 'yaml'
require_relative 'actor_store'
require_relative 'import-malwarebazaar'
require_relative 'import-urlhaus'

class ObservableImportersTest < Minitest::Test
  ROOT = File.expand_path('../test/fixtures/source_imports', __dir__)

  def test_malwarebazaar_quarantines_invalid_and_deduplicates
    assert_report('malwarebazaar', File.join(ROOT, 'malwarebazaar', 'partial.json'), 1, 1)
  end

  def test_urlhaus_quarantines_invalid_and_deduplicates
    assert_report('urlhaus', File.join(ROOT, 'urlhaus', 'partial.json'), 1, 1)
  end

  def test_urlhaus_fetch_sends_shared_abusech_auth_key
    Dir.mktmpdir do |dir|
      requests = []
      response = Net::HTTPOK.new('1.1', '200', 'OK')
      response.define_singleton_method(:body) { '{"query_status":"no_results","data":[]}' }
      fake_http = Object.new
      fake_http.define_singleton_method(:request) do |request|
        requests << request
        response
      end
      singleton = Net::HTTP.singleton_class
      singleton.class_eval do
        alias_method :__urlhaus_auth_test_start, :start
        define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
      end
      previous = ENV['THREATFOX_API_KEY']
      ENV['THREATFOX_API_KEY'] = "shared-test-key\n"
      UrlhausImporter.new.run(['fetch', '--output', dir])
      request = requests.fetch(0)
      assert_instance_of Net::HTTP::Get, request
      assert_equal 'shared-test-key', request['Auth-Key']
      manifest = YAML.safe_load(File.read(File.join(dir, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal 'no_results', manifest['query_status']
    ensure
      ENV['THREATFOX_API_KEY'] = previous
      singleton.class_eval do
        alias_method :start, :__urlhaus_auth_test_start
        remove_method :__urlhaus_auth_test_start
      end
    end
  end

  def test_urlhaus_http_200_auth_error_is_preserved_and_rejected
    Dir.mktmpdir do |dir|
      response = Net::HTTPOK.new('1.1', '200', 'OK')
      response.define_singleton_method(:body) { '{"query_status":"no_auth_key","data":[]}' }
      fake_http = Object.new
      fake_http.define_singleton_method(:request) { |_request| response }
      singleton = Net::HTTP.singleton_class
      singleton.class_eval do
        alias_method :__urlhaus_status_test_start, :start
        define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
      end
      UrlhausImporter.new.run(['fetch', '--output', dir])
      manifest = YAML.safe_load(File.read(File.join(dir, 'manifest.yml')), permitted_classes: [], aliases: false)
      assert_equal 'no_auth_key', manifest['query_status']
      error = assert_raises(RuntimeError) { UrlhausImporter.new.send(:process_snapshot, dir, report_path: nil) }
      assert_includes error.message, 'source status is no_auth_key'
    ensure
      singleton.class_eval do
        alias_method :start, :__urlhaus_status_test_start
        remove_method :__urlhaus_status_test_start
      end
    end
  end

  def test_urlhaus_http_200_missing_data_fails_closed
    Dir.mktmpdir do |dir|
      response = Net::HTTPOK.new('1.1', '200', 'OK')
      response.define_singleton_method(:body) { '{"query_status":"ok"}' }
      fake_http = Object.new
      fake_http.define_singleton_method(:request) { |_request| response }
      singleton = Net::HTTP.singleton_class
      singleton.class_eval do
        alias_method :__urlhaus_shape_test_start, :start
        define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
      end
      error = assert_raises(RuntimeError) { UrlhausImporter.new.run(['fetch', '--output', dir]) }
      assert_includes error.message, 'response data must be an array'
    ensure
      singleton.class_eval do
        alias_method :start, :__urlhaus_shape_test_start
        remove_method :__urlhaus_shape_test_start
      end
    end
  end

  def test_malformed_snapshots_fail_closed
    [
      [MalwareBazaarImporter, File.join(ROOT, 'malwarebazaar', 'malformed.payload')],
      [UrlhausImporter, File.join(ROOT, 'urlhaus', 'malformed.payload')]
    ].each do |klass, path|
      error = assert_raises(RuntimeError) { klass.new.send(:process_snapshot, path, report_path: nil) }
      assert_match(/malformed/, error.message)
    end
  end

  def test_conflicting_duplicate_claims_are_quarantined_and_never_written
    Dir.mktmpdir do |dir|
      data = [{ 'sha256_hash' => 'a' * 64, 'actor' => 'Alpha' }, { 'sha256_hash' => 'a' * 64, 'actor' => 'Beta' }]
      path = File.join(dir, 'data.json')
      File.write(path, JSON.generate(data))
      File.write(File.join(dir, 'manifest.yml'), YAML.dump('retrieved_at' => Time.now.utc.iso8601,
                                                            'source_checksum_sha256' => Digest::SHA256.file(path).hexdigest,
                                                            'data_file' => 'data.json', 'query_status' => 'ok',
                                                            'license_status' => 'abuse.ch terms and fair-use limits apply'))
      report = File.join(dir, 'report.json')
      original_load = ActorStore.method(:load_all)
      original_save = ActorStore.method(:save_all)
      saved = false
      ActorStore.define_singleton_method(:load_all) { [{ 'name' => 'Alpha', 'aliases' => ['Alpha'] }] }
      ActorStore.define_singleton_method(:save_all) { |_actors| saved = true }
      MalwareBazaarImporter.new.send(:process_snapshot, dir, report_path: report, write: true)
      payload = JSON.parse(File.read(report))
      assert_equal 2, payload['total_records']
      assert_equal 1, payload['unmatched']
      assert_equal 1, payload['quarantined']
      refute saved
    ensure
      ActorStore.define_singleton_method(:load_all, original_load) if original_load
      ActorStore.define_singleton_method(:save_all, original_save) if original_save
    end
  end

  def test_snapshot_checksum_is_required
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'data.json')
      File.write(path, JSON.generate([]))
      File.write(File.join(dir, 'manifest.yml'), YAML.dump('retrieved_at' => Time.now.utc.iso8601, 'query_status' => 'ok'))
      error = assert_raises(RuntimeError) { MalwareBazaarImporter.new.send(:process_snapshot, dir, report_path: nil) }
      assert_match(/checksum/, error.message)
    end
  end

  def test_snapshot_file_argument_still_validates_manifest
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'data.json')
      File.write(path, JSON.generate([]))
      File.write(File.join(dir, 'manifest.yml'), YAML.dump('retrieved_at' => Time.now.utc.iso8601,
                                                            'source_checksum_sha256' => Digest::SHA256.file(path).hexdigest,
                                                            'data_file' => 'data.json', 'query_status' => 'ok'))
      error = assert_raises(RuntimeError) { MalwareBazaarImporter.new.send(:process_snapshot, path, report_path: nil, write: true) }
      assert_match(/terms/, error.message)
    end
  end

  private

  def assert_report(source, snapshot, expected_records, expected_quarantined)
    Dir.mktmpdir do |dir|
      report = File.join(dir, 'report.json')
      klass = source == 'urlhaus' ? UrlhausImporter : MalwareBazaarImporter
      klass.new.send(:process_snapshot, snapshot, report_path: report)
      payload = JSON.parse(File.read(report))
      assert_equal expected_records, payload['records']
      assert_equal expected_quarantined, payload['quarantined']
    end
  end
end
