require_relative 'core'

require "test/unit"

class TestBiocVersion < Test::Unit::TestCase

  def test_simple
    assert_equal(0, BiocVersion.new("0.99.0").compare(BiocVersion.new("0.99.0")))
    assert_equal(1, BiocVersion.new("0.99.1").compare(BiocVersion.new("0.99.0")))
    assert_equal(-1, BiocVersion.new("0.99.0").compare(BiocVersion.new("0.99.1")))
    assert_equal(-1, BiocVersion.new("0.98.0").compare(BiocVersion.new("0.99.0")))
    assert_equal(-1, BiocVersion.new("0.99.0").compare(BiocVersion.new("1.99.0")))
    assert_equal(-1, BiocVersion.new("0.99.0").compare(BiocVersion.new("0.100.0")))


    assert_raise(InvalidSegmentNumberError) {BiocVersion.new("haha")}
    assert_raise(InvalidCharacterError) {BiocVersion.new("1.a.2")}
    assert_raise(InvalidCharacterError) {BiocVersion.new("1.2.-3")}
    # hmmm:
    assert_raise(InvalidCharacterError) {BiocVersion.new("0.099.0")}
  end

end

class TestDetectVersionBump < Test::Unit::TestCase

  def test_simple
    assert_equal(true,
      Core.does_patch_have_version_bump?("-Version: 0.99.0\n+Version: 0.99.1"))
    assert_equal(true,
      Core.does_patch_have_version_bump?("+Version: 0.99.1\n-Version: 0.99.0"))
    assert_equal(true,
      Core.does_patch_have_version_bump?("+Version: 0.99.1\r-Version: 0.99.0"))
    assert_equal(true,
      Core.does_patch_have_version_bump?("-Version: 0.99.0\r\n+Version: 0.99.1\n"))
    assert_equal(false, Core.does_patch_have_version_bump?("a bunch\nof garbage"))
    assert_equal(false,
      Core.does_patch_have_version_bump?("-Version: 0.99.0\n+Version: 0.99.0"))
    assert_equal(false,
      Core.does_patch_have_version_bump?("-Version: 0.99.1\n+Version: 0.99.0"))
    assert_equal(false,
      Core.does_patch_have_version_bump?("-Version: 0.99.0\nhahahah\n"))
    assert_equal(false,
      Core.does_patch_have_version_bump?("-Version: 0.99.0.0\n+Version: 0.99.0"))
  end
end
