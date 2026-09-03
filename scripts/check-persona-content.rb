#!/usr/bin/env ruby

FORBIDDEN_TERMS = [
  'zack korman',
  'zack-korman',
  'zackware',
  'breachbro',
  'zackstealer',
  'forgemail',
  'custom skill collections',
  'zkorman.com',
  'github.com/zackkorman',
  'parody/persona test actor'
].freeze

PUBLISHED_PATHS = %w[
  _data/actors
  _data/analyst_notes
  _data/generated
  _threat_actors
  _malware
  api
  _site
].freeze

files = PUBLISHED_PATHS.flat_map { |path| Dir.glob(File.join(path, '**', '*')) }
files.select! { |path| File.file?(path) }
files.reject! { |path| path.start_with?('_site/scripts/') }

violations = files.flat_map do |path|
  content = File.read(path, mode: 'rb')
  content.force_encoding(Encoding::UTF_8)
  content.lines.each_with_index.filter_map do |line, index|
    normalized_line = line.encode('UTF-8', invalid: :replace, undef: :replace).downcase
    term = FORBIDDEN_TERMS.find { |candidate| normalized_line.include?(candidate) }
    "#{path}:#{index + 1}: forbidden persona term #{term.inspect}" if term
  end
end

if violations.empty?
  puts "Persona content check passed (#{files.length} published files scanned)."
else
  warn violations.join("\n")
  exit 1
end
