# frozen_string_literal: true

Signal.trap('TERM') { }
sleep 30
exit 0
