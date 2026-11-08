# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../scripts/lib/news_feed'
require_relative '../scripts/fetch-news'

# Mocked HTTP only — proves CISA-style 403 / HTML soft-block advances to an
# alternate URL and that the successful body still parses into items.
# Deadlines are generous so these stay timing-stable on slow CI.
class FetchNewsCisaFallbackTest < Minitest::Test
  CISA_FEED = {
    name: 'CISA Advisories',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    alternate_urls: [
      'https://www.cisa.gov/news.xml',
      'https://www.cisa.gov/uscert/ncas/alerts.xml'
    ],
    weight: 2,
    category: :security
  }.freeze

  VALID_RSS = <<~XML
    <?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>CISA</title>
        <item>
          <title>CISA Adds Actively Exploited Vulnerability to KEV Catalog</title>
          <link>https://www.cisa.gov/news-events/alerts/2026/11/06/example</link>
          <pubDate>Thu, 06 Nov 2026 12:00:00 GMT</pubDate>
        </item>
        <item>
          <title>CISA Releases Cybersecurity Advisory on Ransomware</title>
          <link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-000a</link>
          <pubDate>Wed, 05 Nov 2026 12:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>
  XML

  def stub_open_feed_within_budget(&handler)
    attempts = []
    original = Object.instance_method(:open_feed_within_budget)
    Object.define_method(:open_feed_within_budget) do |url, deadline|
      attempts << url
      handler.call(url, deadline)
    end
    [attempts, original]
  end

  def restore_open_feed_within_budget(original)
    Object.define_method(:open_feed_within_budget, original)
  end

  def test_cisa_403_on_primary_falls_back_and_parses_items
    attempts, original = stub_open_feed_within_budget do |url, _deadline|
      raise StandardError, 'HTTP 403 Forbidden' if url.include?('all.xml')

      VALID_RSS
    end

    begin
      result = fetch_and_parse_feed_within_deadline(CISA_FEED, deadline_seconds: 10)
    ensure
      restore_open_feed_within_budget(original)
    end

    assert_equal 'https://www.cisa.gov/news.xml', result[:url]
    assert_equal 2, result[:items].size
    assert_match(/KEV Catalog/, result[:items].first[:title])
    assert_equal(
      %w[
        https://www.cisa.gov/cybersecurity-advisories/all.xml
        https://www.cisa.gov/news.xml
      ],
      attempts
    )
    assert_operator result[:fetch_ms], :>=, 0
    assert_operator result[:parse_ms], :>=, 0
  end

  def test_cisa_html_soft_block_advances_to_alternate
    html_denied = "<!DOCTYPE html><html><body>Access Denied</body></html>\n"
    attempts, original = stub_open_feed_within_budget do |url, _deadline|
      if url.include?('all.xml')
        html_denied
      else
        VALID_RSS
      end
    end

    begin
      result = fetch_and_parse_feed_within_deadline(CISA_FEED, deadline_seconds: 10)
    ensure
      restore_open_feed_within_budget(original)
    end

    assert_equal 'https://www.cisa.gov/news.xml', result[:url]
    assert_operator result[:items].size, :>=, 1
    assert_equal(
      %w[
        https://www.cisa.gov/cybersecurity-advisories/all.xml
        https://www.cisa.gov/news.xml
      ],
      attempts
    )
  end

  def test_all_cisa_urls_failing_surfaces_last_error
    _attempts, original = stub_open_feed_within_budget do |_url, _deadline|
      raise StandardError, 'HTTP 403 Forbidden'
    end

    begin
      err = assert_raises(StandardError) do
        fetch_and_parse_feed_within_deadline(CISA_FEED, deadline_seconds: 10)
      end
      assert_match(/403/, err.message)
    ensure
      restore_open_feed_within_budget(original)
    end
  end
end
