# frozen_string_literal: true

require 'minitest/autorun'
require 'timeout'
require_relative '../scripts/lib/news_feed'

# Keep this file free of `require 'fetch-news'` side effects where possible.
# The production wiring (fetch + parse under one deadline) lives in
# scripts/fetch-news.rb; here we prove the shared primitive and the health
# mapping that script relies on.
class FetchNewsParseDeadlineTest < Minitest::Test
  def test_slow_parse_like_work_counts_as_deadline_exceeded
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    err = assert_raises(Timeout::Error) do
      NewsFeed.run_with_deadline(0.4) do
        # Simulate a fast "fetch" then a stuck RSS::Parser.parse.
        _fetch_body = '<rss/>'
        sleep 5
        :parsed
      end
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert_match(/deadline exceeded/i, err.message)
    assert_operator elapsed, :<, 2.5, "parse-phase deadline leaked: #{elapsed}s"
  end

  def test_parse_timeout_is_recorded_as_timed_out_health
    previous = {}
    entry = {
      'ok' => false,
      'error' => "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)",
      'items' => 0,
      'latency_ms' => 450,
      'timed_out' => true
    }
    merged = NewsFeed.merge_source_health_entry(entry, previous)
    assert merged['timed_out']
    refute merged['ok']
    assert_equal 1, merged['consecutive_failures']
    refute merged['unhealthy']
  end

  def test_trim_then_deadline_allows_fast_success_path
    items_xml = (1..40).map { |i|
      "<item><title>T#{i}</title><link>https://ex.test/#{i}</link></item>"
    }.join
    raw = "<?xml version=\"1.0\"?><rss><channel><title>x</title>#{items_xml}</channel></rss>"

    result = NewsFeed.run_with_deadline(2) do
      trimmed = NewsFeed.trim_feed_xml(raw, max_items: NewsFeed::MAX_PER_FEED)
      assert_equal NewsFeed::MAX_PER_FEED, trimmed.scan(/<item>/).size
      {
        fetch_ms: 1,
        parse_ms: 2,
        items: trimmed.scan(/<item>/).size
      }
    end

    assert_equal NewsFeed::MAX_PER_FEED, result[:items]
    assert_equal 1, result[:fetch_ms]
    assert_equal 2, result[:parse_ms]
  end
end
