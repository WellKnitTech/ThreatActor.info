#!/usr/bin/env ruby
# frozen_string_literal: true

# Beazley Security Labs feed fetcher
require 'open-uri'
require 'rexml/document'

def fetch_beazley_articles
  feeds = [
    { url: 'https://labs.beazley.security/articles/atom.xml', source: 'Beazley Security Labs Articles' },
    { url: 'https://labs.beazley.security/advisories/atom.xml', source: 'Beazley Security Labs Advisories' }
  ]
  articles = []

  feeds.each do |feed|
    begin
      raw = URI.parse(feed[:url]).open(read_timeout: 10).read
      articles.concat(parse_beazley_atom_entries(raw, feed[:source]))
    rescue => e
      puts "Beazley #{feed[:source]}: #{e.message[0..40]}"
    end
  end

  articles.uniq { |item| item[:link] }
end

def parse_beazley_atom_entries(xml, source)
  doc = REXML::Document.new(xml)
  entries = []

  REXML::XPath.each(doc, '//entry') do |entry|
    title = entry.elements['title']&.text&.strip
    link = entry.elements['link']&.attributes&.[]('href')&.strip
    published = entry.elements['published']&.text&.strip || entry.elements['updated']&.text&.strip
    next if title.to_s.empty? || link.to_s.empty?

    entries << {
      title: title[0..200],
      link: link,
      source: source,
      date: published
    }
  end

  entries.first(15)
end

# Test
puts "Fetching Beazley Security Labs articles..."
arts = fetch_beazley_articles
puts "Found #{arts.size} articles"
arts.first(5).each do |a|
  puts "- #{a[:title][0..60]}"
  puts "  #{a[:link]}"
end
