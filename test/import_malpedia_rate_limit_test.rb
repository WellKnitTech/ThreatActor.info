#!/usr/bin/env ruby
# frozen_string_literal: true

require 'minitest/autorun'
require 'net/http'
require_relative '../scripts/import-malpedia'

class MalpediaRateLimitTest < Minitest::Test
  URL = URI('https://example.test/api/get/actor/example')

  def test_429_raises_rate_limit_error_with_retry_after
    response = Net::HTTPTooManyRequests.new('1.1', '429', 'Too Many Requests')
    response['Retry-After'] = '120'
    fake_http = Object.new
    fake_http.define_singleton_method(:request) { |_request| response }
    singleton = Net::HTTP.singleton_class
    singleton.class_eval do
      alias_method :__malpedia_rate_limit_test_start, :start
      define_method(:start) { |_host, _port, **_kwargs, &block| block.call(fake_http) }
    end

    importer = MalpediaImporter.new([])
    error = assert_raises(MalpediaImporter::RateLimitError) do
      importer.send(:http_get_json, URL)
    end

    assert_equal 'HTTP 429 for https://example.test/api/get/actor/example; Retry-After=120', error.message
    metrics = importer.instance_variable_get(:@request_metrics)
    assert_equal 1, metrics['request_count']
    assert_equal 0, metrics['response_bytes']
  ensure
    singleton.class_eval do
      remove_method :start
      alias_method :start, :__malpedia_rate_limit_test_start
      remove_method :__malpedia_rate_limit_test_start
    end
  end
end
