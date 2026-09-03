#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'minitest/autorun'
require 'tmpdir'
require 'yaml'
require_relative '../scripts/import-mitre'

class MitreConditionalFetchTest < Minitest::Test
  URL = 'https://example.test/enterprise.json'

  def test_prior_bundle_requires_matching_url_and_verified_checksum
    Dir.mktmpdir do |dir|
      body = '{"type":"bundle"}'
      filename = 'enterprise-attack.json'
      File.binwrite(File.join(dir, filename), body)
      manifest = { 'bundles' => { 'enterprise' => {
        'url' => URL, 'filename' => filename,
        'sha256' => Digest::SHA256.hexdigest(body),
        'response' => { 'etag' => '"v1"' }
      } } }
      File.write(File.join(dir, 'manifest.yml'), YAML.dump(manifest))
      importer = MitreAttackImporter.new([])
      importer.instance_variable_set(:@options, prior_snapshot: dir)

      info, path = importer.send(:prior_bundle, 'enterprise', URL)
      assert_equal '"v1"', info.dig('response', 'etag')
      assert_equal File.join(dir, filename), path

      File.binwrite(File.join(dir, filename), 'tampered')
      assert_equal [nil, nil], importer.send(:prior_bundle, 'enterprise', URL)
    end
  end

  def test_304_reuses_verified_snapshot_and_sends_validators
    Dir.mktmpdir do |dir|
      prior = File.join(dir, 'prior.json')
      output = File.join(dir, 'output.json')
      File.binwrite(prior, 'stable snapshot')
      requests = []
      response = Net::HTTPNotModified.new('1.1', '304', 'Not Modified')
      fake_http = Object.new
      fake_http.define_singleton_method(:request) do |request|
        requests << request
        response
      end
      singleton = Net::HTTP.singleton_class
      singleton.class_eval do
        alias_method :__conditional_test_start, :start
        define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
      end
      importer = MitreAttackImporter.new([])
      result = importer.send(:download, URL, output,
                              prior_info: { 'etag' => '"v1"', 'last_modified' => 'yesterday' },
                              prior_path: prior)

      assert_equal 'not_modified', result['status']
      assert_equal 0, result['bytes']
      assert_equal File.size(prior), result['copied_bytes']
      assert_equal File.binread(prior), File.binread(output)
      assert_equal '"v1"', requests.first['If-None-Match']
      assert_equal 'yesterday', requests.first['If-Modified-Since']
    ensure
      singleton.class_eval do
        remove_method :start
        alias_method :start, :__conditional_test_start
        remove_method :__conditional_test_start
      end
    end
  end

  def test_304_reuse_does_not_copy_snapshot_onto_itself
    Dir.mktmpdir do |dir|
      snapshot = File.join(dir, 'snapshot.json')
      File.binwrite(snapshot, 'stable snapshot')
      response = Net::HTTPNotModified.new('1.1', '304', 'Not Modified')
      fake_http = Object.new
      fake_http.define_singleton_method(:request) { |_request| response }
      singleton = Net::HTTP.singleton_class
      singleton.class_eval do
        alias_method :__conditional_same_path_test_start, :start
        define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
      end

      importer = MitreAttackImporter.new([])
      result = importer.send(:download, URL, snapshot,
                             prior_info: { 'etag' => '"v1"' }, prior_path: snapshot)

      assert_equal 'not_modified', result['status']
      assert_equal 0, result['bytes']
      assert_equal 'stable snapshot', File.binread(snapshot)
    ensure
      singleton.class_eval do
        remove_method :start
        alias_method :start, :__conditional_same_path_test_start
        remove_method :__conditional_same_path_test_start
      end
    end
  end
end
