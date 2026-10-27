# frozen_string_literal: true

# Runs independent source jobs with a bounded worker pool. Results stay in input
# order; fail-fast prevents queued work from starting, while active work drains.
#
# fail_fast may be true, false, or a callable that receives the failed item and
# returns whether remaining queued work should be cancelled (e.g. only cancel
# after a critical source fails).
module SourceImport
  class BoundedSourceRunner
    Result = Struct.new(:item, :value, :error, :skipped, keyword_init: true)

    def initialize(items, workers:, fail_fast: true)
      @items = items
      @workers = Integer(workers)
      raise ArgumentError, 'workers must be positive' unless @workers.positive?
      @fail_fast = fail_fast
    end

    def run
      queue = Queue.new
      @items.each_with_index { |item, index| queue << [index, item] }
      results = Array.new(@items.length)
      mutex = Mutex.new
      cancelled = false
      threads = Array.new([@workers, @items.length].min) do
        Thread.new do
          loop do
            index, item = queue.pop(true)
            should_skip = mutex.synchronize do
              if cancelled
                results[index] = Result.new(item: item, skipped: true)
                true
              else
                false
              end
            end
            next if should_skip
            begin
              value = yield(item)
              results[index] = Result.new(item: item, value: value)
            rescue StandardError => error
              results[index] = Result.new(item: item, error: error)
              mutex.synchronize { cancelled = true } if fail_fast_for?(item)
            end
          rescue ThreadError
            break
          end
        end
      end
      threads.each(&:join)
      results.each_with_index do |result, index|
        results[index] ||= Result.new(item: @items[index], skipped: true)
      end
      results
    end

    private

    def fail_fast_for?(item)
      case @fail_fast
      when true then true
      when false then false
      else
        @fail_fast.call(item)
      end
    end
  end
end
