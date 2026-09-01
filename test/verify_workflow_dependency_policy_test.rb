# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require 'rbconfig'
require 'tmpdir'

class VerifyWorkflowDependencyPolicyTest < Minitest::Test
  SCRIPT = File.expand_path('../scripts/verify-workflow-dependency-policy.rb', __dir__)
  WORKFLOWS = File.expand_path('../.github/workflows', __dir__)

  def test_current_workflows_pass
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, SCRIPT, WORKFLOWS)

    assert status.success?, "#{stdout}\n#{stderr}"
  end

  def test_redundant_install_is_rejected
    Dir.mktmpdir do |directory|
      path = File.join(directory, 'bad.yml')
      File.write(path, "steps:\n  - uses: ruby/setup-ruby@v1\n    with:\n      bundler-cache: true\n  - run: bundle install\n")

      _stdout, stderr, status = Open3.capture3(RbConfig.ruby, SCRIPT, directory)
      refute status.success?, stderr
    end
  end
end