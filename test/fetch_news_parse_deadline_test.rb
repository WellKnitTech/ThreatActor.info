# frozen_string_literal: true

require 'minitest/autorun'
require 'timeout'
require_relative '../scripts/lib/news_feed'
require_relative '../scripts/fetch-news'

class FetchNewsParseDeadlineTest < Minitest::Test
  def with_top_level_override(name, impl)
    mod = Object
    original = mod.instance_method(name)
    mod.define_method(name, &impl)
    yield
  ensure
    mod.define_method(name, original)
  end

  def test_slow_parse_counts_as_timed_out
    feed = {
      name: 'SlowParseFeed',
      url: 'https://example.test/feed.xml',
      weight: 1,
      category: :security
    }

    with_top_level_override(:open_feed_within_budget, proc { |_url, _remaining|
      '<?xml version="1.0"?><rss><channel></channel></rss>'
    }) do
      with_top_level_override(:parse_feed_items, proc { |_raw, _feed|
        sleep 5
        [[{
          title: 'x',
          link: 'https://example.test/x',
          date: Time.now.utc,
          source: 'SlowParseFeed',
          weight: 1,
          category: :security
        }], nil]
      }) do
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        err = assert_raises(Timeout::Error) do
          fetch_and_parse_feed_within_deadline(feed, deadline_seconds: 0.4)
        end
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

        assert_match(/deadline exceeded/i, err.message)
        assert_operator elapsed, :<, 2.5, "parse deadline leaked: #{elapsed}s"
      end
    end

    # parse_feed wires Timeout::Error into source_health timed_out=true
    health = {}
    with_top_level_override(:fetch_and_parse_feed_within_deadline, proc { |_feed, **_kwargs|
      raise Timeout::Error, "deadline exceeded (#{NewsFeed::FEED_DEADLINE_SECONDS}s)"
    }) do
      items = parse_feed(feed, health, previous_entry: {})
      assert_equal [], items
      assert health['SlowParseFeed']['timed_out']
      refute health['SlowParseFeed']['ok']
      assert_match(/deadline exceeded/i, health['SlowParseFeed']['error'])
    end
  end

  def test_phase_timing_recorded_on_success
    feed = {
      name: 'FastFeed',
      url: 'https://example.test/fast.xml',
      weight: 1,
      category: :security
    }
    raw = <<~XML
      <?xml version="1.0"?>
      <rss version="2.0"><channel><title>t</title>
        <item><title>Alpha</title><link>https://example.test/a</link><pubDate>Mon, 02 Nov 2026 00:00:00 GMT</pubDate></item>
        <item><title>Beta</title><link>https://example.test/b</link><pubDate>Mon, 02 Nov 2026 01:00:00 GMT</pubDate></item>
      </channel></rss>
    XML

    with_top_level_override(:open_feed_within_budget, proc { |_url, _remaining| raw }) do
      result = fetch_and_parse_feed_within_deadline(feed, deadline_seconds: 10)
      assert_operator result[:items].size, :>=, 1
      assert_kind_of Integer, result[:fetch_ms]
      assert_kind_of Integer, result[:parse_ms]
      assert_operator result[:fetch_ms], :>=, 0
      assert_operator result[:parse_ms], :>=, 0
    end
  end
end
