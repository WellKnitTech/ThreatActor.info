# frozen_string_literal: true

require 'minitest/autorun'
require 'yaml'

class ObservableSourcePolicyTest < Minitest::Test
  POLICY = File.expand_path('../data/observable-source-policy.yml', __dir__)

  def setup
    @policy = YAML.safe_load(File.read(POLICY), permitted_classes: [], aliases: false)
  end

  def test_threatfox_uses_machine_readable_seven_day_age_gate
    threatfox = @policy.fetch('sources').fetch('threatfox')

    assert_equal 7, threatfox.fetch('max_age_days')
    assert_kind_of Integer, threatfox.fetch('max_age_days')
  end

  def test_registered_source_types_use_observable_v1_ip_address
    @policy.fetch('sources').each_value do |source|
      refute_includes Array(source['supported_types']), 'ipv4'
      refute_includes Array(source['supported_types']), 'ipv6'
    end

    assert_includes @policy.fetch('sources').fetch('threatfox').fetch('supported_types'), 'ip_address'
  end

  def test_every_registered_source_has_a_correction_contact
    @policy.fetch('sources').each do |source_key, source|
      contact = source['correction_contact'].to_s
      assert_match(%r{\Ahttps://}, contact, "#{source_key} lacks correction contact")
    end
  end
end
