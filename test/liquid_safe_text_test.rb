# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require_relative '../scripts/lib/liquid_safe_text'
require_relative '../scripts/validate-content'

class LiquidSafeTextTest < Minitest::Test
  def test_unwraps_single_etda_cross_ref
    assert_equal 'Uses Hacking Team implants', LiquidSafeText.sanitize('Uses {{Hacking Team}} implants')
  end

  def test_unwraps_multi_alias_etda_cross_ref
    assert_equal(
      'TA505 (Graceful Spider, Gold Evergreen)',
      LiquidSafeText.sanitize('{{TA505, Graceful Spider, Gold Evergreen}}')
    )
  end

  def test_unwraps_subgroup_style_marker
    assert_equal(
      'Subgroup: [Unnamed group USA]',
      LiquidSafeText.sanitize('{{Subgroup: [Unnamed group USA]}}')
    )
  end

  def test_neutralizes_unclosed_liquid_variable
    text = 'Attribution notes mention {{ without a closing brace'
    sanitized = LiquidSafeText.sanitize(text)
    refute_includes sanitized, '{{'
    assert_includes sanitized, 'without a closing brace'
  end

  def test_preserves_citation_placeholders_as_footnote_markers
    assert_equal 'See [#1] and [#2]', LiquidSafeText.sanitize('See {{citation:1}} and {{2}}')
  end

  def test_neutralizes_liquid_tag_delimiters
    assert_equal 'raw tag', LiquidSafeText.sanitize('{% raw tag %}')
    refute LiquidSafeText.contains_liquid_delimiters?(LiquidSafeText.sanitize('{% if true %}'))
  end

  def test_contains_liquid_delimiters_detection
    assert LiquidSafeText.contains_liquid_delimiters?('{{TA505}}')
    assert LiquidSafeText.contains_liquid_delimiters?('{% assign x = 1 %}')
    refute LiquidSafeText.contains_liquid_delimiters?('plain prose')
  end
end

class CollectionLiquidDelimiterValidationTest < Minitest::Test
  def test_validate_content_flags_raw_liquid_in_threat_actor_body
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        FileUtils.mkdir_p('_threat_actors')
        File.write('_threat_actors/avalanche.md', <<~MD)
          ---
          layout: threat_actor
          title: Avalanche
          ---

          ## Introduction
          Linked to {{TA505, Graceful Spider, Gold Evergreen}}.
        MD

        validator = ContentValidator.new
        validator.send(:validate_collection_liquid_delimiters)
        errors = validator.instance_variable_get(:@errors)

        assert errors.any? { |e| e[:file] == '_threat_actors/avalanche.md' }
        assert errors.any? { |e| e[:message].include?('Liquid delimiter') }
      end
    end
  end

  def test_validate_content_accepts_sanitized_bodies
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        FileUtils.mkdir_p('_threat_actors')
        File.write('_threat_actors/avalanche.md', <<~MD)
          ---
          layout: threat_actor
          title: Avalanche
          ---

          ## Introduction
          Linked to TA505 (Graceful Spider, Gold Evergreen).
        MD

        validator = ContentValidator.new
        validator.send(:validate_collection_liquid_delimiters)
        errors = validator.instance_variable_get(:@errors)

        assert_empty errors
      end
    end
  end
end
