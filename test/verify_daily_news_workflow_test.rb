# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tempfile'
require 'timeout'

class VerifyDailyNewsWorkflowTest < Minitest::Test
  SCRIPT = File.expand_path('../scripts/verify-daily-news-workflow.rb', __dir__)
  WORKFLOW = File.expand_path('../.github/workflows/daily-news.yml', __dir__)

  def run_checker(contents)
    Tempfile.create(['daily-news', '.yml']) do |file|
      file.write(contents)
      file.flush
      Timeout.timeout(3) { Open3.capture3(RbConfig.ruby, SCRIPT, file.path) }
    end
  end

  def test_current_workflow_passes
    _stdout, stderr, status = run_checker(File.read(WORKFLOW))

    assert status.success?, stderr
  end

  def test_dispatch_requires_actions_write_and_push_gate
    workflow = File.read(WORKFLOW)
    pages = File.read(File.expand_path('../.github/workflows/pages.yml', __dir__))
    validate = File.read(File.expand_path('../.github/workflows/validate.yml', __dir__))

    assert_match(/actions:\s*write/, workflow)
    assert_match(/steps\.commit\.outputs\.changed\s*==\s*'true'/, workflow)
    assert_match(/steps\.push\.outputs\.pushed\s*==\s*'true'/, workflow)
    assert_match(/gh\s+workflow\s+run\s+\"Deploy GitHub Pages\"\s+--ref\s+main/, workflow)
    assert_match(/gh\s+workflow\s+run\s+\"Content Validation\"\s+--ref\s+main/, workflow)
    assert_match(/workflow_dispatch:/, pages)
    assert_match(/workflow_dispatch:/, validate)
  end

  def test_missing_dispatch_is_rejected
    poisoned = File.read(WORKFLOW)
      .gsub(/gh workflow run "Deploy GitHub Pages" --ref main/, 'echo skip-pages')
      .gsub(/actions:\s*write/, 'actions: read')
    refute_equal File.read(WORKFLOW), poisoned

    _stdout, stderr, status = run_checker(poisoned)
    refute status.success?, stderr
    assert_match(/actions: write|Deploy GitHub Pages/i, stderr)
  end
end
