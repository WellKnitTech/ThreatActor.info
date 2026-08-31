# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tempfile'
require 'timeout'

class VerifyWeeklyDataWorkflowTest < Minitest::Test
  SCRIPT = File.expand_path('../scripts/verify-weekly-data-workflow.rb', __dir__)
  WORKFLOW = File.expand_path('../.github/workflows/weekly-data.yml', __dir__)

  def run_checker(contents)
    Tempfile.create(['weekly-data', '.yml']) do |file|
      file.write(contents)
      file.flush
      Timeout.timeout(3) { Open3.capture3(RbConfig.ruby, SCRIPT, file.path) }
    end
  end

  def test_current_workflow_passes
    _stdout, stderr, status = run_checker(File.read(WORKFLOW))

    assert status.success?, stderr
  end

  def test_malformed_permissions_input_is_rejected_without_backtracking
    workflow = "jobs:\n  update-data:\n    runs-on: ubuntu-latest\n" + ("\t\t\n" * 10_000)

    _stdout, stderr, status = run_checker(workflow)

    refute status.success?, stderr
  end
end
