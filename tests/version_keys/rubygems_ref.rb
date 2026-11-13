# rubygems_ref.rb: the RubyGems reference for the tests. It answers with Ruby's own Gem::Version,
# the order Bundler uses.
#
# Reads lines "a<TAB>b" from stdin and writes one line each: -1, 0 or 1 for Gem::Version a <=> b,
# or ERR when Gem::Version.correct? refuses a or b.
# With the argument "valid" it reads one version a line and writes 1 or 0 (correct? or not).
# With the argument "sort" it reads one version a line and writes those Ruby accepts, in order.
require "rubygems"

if ARGV[0] == "sort"
  puts $stdin.each_line.map { |line| line.chomp("\n") }.select { |v| Gem::Version.correct?(v) }.sort_by { |v| Gem::Version.new(v) }
elsif ARGV[0] == "valid"
  $stdin.each_line do |line|
    puts(Gem::Version.correct?(line.chomp("\n")) ? 1 : 0)
  end
else
  $stdin.each_line do |line|
    a, b = line.chomp("\n").split("\t", 2)
    if b.nil? || !Gem::Version.correct?(a) || !Gem::Version.correct?(b)
      puts "ERR"
    else
      puts(Gem::Version.new(a) <=> Gem::Version.new(b))
    end
  end
end
