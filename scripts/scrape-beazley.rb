#!/usr/bin/env ruby
# frozen_string_literal: true

# Beazley Security Labs scraper (no nokogiri)
require 'open-uri'

def fetch_beazley_articles
  articles = []
  
  begin
    url = "https://labs.beazley.security/articles"
    html = URI.parse(url).open(read_timeout: 10).read
    
    # Find article links using regex
    # Pattern: <a href="/articles/slug">Title</a>
    html.scan(/<a href="(\/articles\/[^"]+)"[^>]*>([^<]+)<\/a>/).first(15).each do |match|
      href, title = match
      next if title.strip.empty?
      
      full_url = "https://labs.beazley.security#{href}"
      articles << {
        title: title.strip[0..200],
        link: full_url,
        source: 'Beazley Security Labs',
        date: nil
      }
    end
  rescue => e
    puts "Beazley: #{e.message[0..40]}"
  end
  
  articles
end

# Test
puts "Fetching Beazley Security Labs articles..."
arts = fetch_beazley_articles
puts "Found #{arts.size} articles"
arts.first(5).each do |a|
  puts "- #{a[:title][0..60]}"
  puts "  #{a[:link]}"
end