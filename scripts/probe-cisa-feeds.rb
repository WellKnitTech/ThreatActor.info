#!/usr/bin/env ruby
# frozen_string_literal: true

# Live probe for CISA feed URLs / header variants. Not part of validate.sh.
# Run: ruby scripts/probe-cisa-feeds.rb
#
# Prints which configured CISA URLs return usable RSS/Atom, and whether a
# bare Ruby UA still 403s while browser-like headers succeed.

require_relative 'lib/news_feed'

URLS = NewsFeed.feed_urls(
  NewsFeed::RSS_FEEDS.find { |f| f[:name] == 'CISA Advisories' }
).freeze

def probe(url, headers, label)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  begin
    body = NewsFeed.http_get_with_timeouts(
      url,
      headers: headers,
      open_timeout: 8,
      read_timeout: 15
    )
    ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
    usable = NewsFeed.feed_body_usable?(body)
    items = body.to_s.scan(/<(?:item|entry)[\s>]/i).size
    puts format('%-18s %4dms usable=%-5s items~%-4d %s', label, ms, usable, items, url)
    { ok: usable, items: items, ms: ms, error: nil }
  rescue StandardError => e
    ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
    puts format('%-18s %4dms ERROR=%s %s', label, ms, e.message.to_s[0, 80], url)
    { ok: false, items: 0, ms: ms, error: e.message }
  end
end

puts '=== Bare Ruby UA (control) ==='
ruby_ua = { 'User-Agent' => 'Ruby' }
URLS.each { |url| probe(url, ruby_ua, 'ruby-ua') }

puts ''
puts '=== Browser-like headers (production) ==='
results = URLS.map do |url|
  probe(url, NewsFeed.browser_http_headers(url: url), 'browser')
end

puts ''
puts '=== Browser UA + Accept only (no Sec-Fetch/Referer) ==='
ua_only = {
  'User-Agent' => NewsFeed::BROWSER_UA,
  'Accept' => 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8',
  'Accept-Language' => 'en-US,en;q=0.9',
  'Accept-Encoding' => 'gzip, deflate'
}
URLS.each { |url| probe(url, ua_only, 'ua+accept') }

usable = results.count { |r| r[:ok] }
puts ''
puts "Summary: #{usable}/#{results.size} configured CISA URLs usable with production browser headers"
exit(usable.positive? ? 0 : 1)
