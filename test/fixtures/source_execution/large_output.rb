# frozen_string_literal: true

10_000.times do |index|
  puts "stdout-#{index}"
  warn "stderr-#{index}"
end
exit 0
