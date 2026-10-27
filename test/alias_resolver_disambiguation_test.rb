# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../scripts/lib/alias_resolver'

class AliasResolverDisambiguationTest < Minitest::Test
  def setup
    @actors = [
      {
        'name' => 'UNC1549',
        'aliases' => ['Nimbus Manticore', 'UNC1549'],
        'url' => '/unc1549/',
        'mitre_id' => 'G1059'
      },
      {
        'name' => 'TA455',
        'aliases' => ['TA455'],
        'url' => '/ta455/'
      },
      {
        'name' => 'Cerber One',
        'aliases' => ['Cerber', 'c3rb3r'],
        'url' => '/cerber-one/'
      },
      {
        'name' => 'Cerber Two',
        'aliases' => ['Cerber'],
        'url' => '/cerber-two/'
      }
    ]
    @index = AliasResolver.build_alias_index(@actors, synonym_path: nil)
  end

  def test_nimbus_manticore_prefers_primary_name_over_ta455_alias_collision
    # MITRE G1059 aliases include both UNC1549 and TA455; primary name must win.
    match = AliasResolver.find_match_extended(
      'NIMBUS MANTICORE',
      ['NIMBUS MANTICORE', 'UNC1549', 'TA455', 'COBALT SMOKEY'],
      @index,
      mitre_id: 'G1059',
      external_id: 'G1059',
      actors: @actors
    )

    assert_equal :high, match[:confidence]
    assert_equal 0, match[:position]
    assert_equal 'UNC1549', @actors[match[:position]]['name']
  end

  def test_ta455_primary_name_wins_even_if_unc1549_also_lists_the_alias
    @actors[0]['aliases'] = ['Nimbus Manticore', 'UNC1549', 'TA455']
    index = AliasResolver.build_alias_index(@actors, synonym_path: nil)
    match = AliasResolver.find_match_extended('TA455', [], index, actors: @actors)

    assert_equal :high, match[:confidence]
    assert_equal 1, match[:position]
    assert_equal 'TA455', @actors[match[:position]]['name']
  end

  def test_mitre_id_disambiguates_when_primary_name_is_shared
    actors = [
      { 'name' => 'Shared', 'aliases' => ['Shared'], 'url' => '/shared-a/', 'mitre_id' => 'G1111' },
      { 'name' => 'Shared', 'aliases' => ['Shared', 'Other'], 'url' => '/shared-b/', 'mitre_id' => 'G2222' }
    ]
    index = AliasResolver.build_alias_index(actors, synonym_path: nil)
    match = AliasResolver.find_match_extended('Shared', ['Other'], index, mitre_id: 'G2222', actors: actors)

    assert_equal :high, match[:confidence]
    assert_equal 1, match[:position]
  end

  def test_leet_alias_collisions_remain_ambiguous_without_unique_primary_name
    match = AliasResolver.find_match_extended('c3rb3r', [], @index, actors: @actors)

    assert_equal :ambiguous, match[:confidence]
    assert_equal [2, 3], match[:positions]
  end
end
