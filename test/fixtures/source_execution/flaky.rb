# frozen_string_literal: true

# First N invocations fail with a retryable 5xx; later invocations succeed.
# State file path is ARGV[0].
path = ARGV.fetch(0)
count = File.exist?(path) ? Integer(File.read(path)) : 0
File.write(path, (count + 1).to_s)
if count.zero?
  warn 'HTTP 503 unavailable'
  exit 1
end
puts 'ok'
exit 0
