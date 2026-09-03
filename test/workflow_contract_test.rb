# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'

class WorkflowContractTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  CHECKER = File.join(ROOT, 'scripts/verify-import-workflow-contract.rb')

  def test_schedule_and_manual_entry_points_resolve_to_canonical_runner
    output, error, status = Open3.capture3('ruby', CHECKER, chdir: ROOT)

    assert status.success?, "#{output}\n#{error}"
    assert_includes output, 'Import workflow contract checks passed.'
  end

  def test_legacy_entry_point_has_no_schedule
    workflow = File.read(File.join(ROOT, '.github/workflows/import-sources.yml'))

    refute_match(/^\s+schedule:/, workflow)
    assert_match(/uses: \.\/\.github\/workflows\/import-pipeline\.yml/, workflow)
  end
end
