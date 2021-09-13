#!/usr/bin/env ruby

#
# Basic script to download the conformance packs, parse them, and produce:
#
#   - A YAML file containing all of the Config Rules associated with each pack
#   - A text file containing only a newline separated list of all the packs
#
# This script is run ad-hoc by the module maintainers and the files are
# committed to this repo, so this is not being run as part of normal Terraform
# operations
#


require 'fileutils'
require 'time'
require 'yaml'

rule_packs      = Array.new
pack_rules_yaml = 'files/pack-rules.yaml'
pack_rules_list = 'files/pack-rules-list.txt'
rules_dir       = 'aws-config-rules'
git_clone       = `git clone https://github.com/awslabs/#{rules_dir}.git`
yaml_files      = Dir["#{rules_dir}/aws-config-conformance-packs/*.yaml"]

packs = {
  "generated_on" => Time.now.utc.iso8601,
  "packs"        => Hash.new,
}

puts ""

yaml_files.sort.each do |file|
  pack = File.basename(file, '.yaml')

  next if pack == 'custom-conformance-pack'

  content = File.read(file)
  parsed  = YAML.safe_load(content)
  rules   = Array.new

  parsed["Resources"].each do |rule, attr|
    if attr["Properties"]["Source"] != nil
      ident = attr["Properties"]["Source"]["SourceIdentifier"]
      rules << ident.downcase.gsub("_", "-")
    end
  end

  packs["packs"][pack] = rules.uniq.sort
  rule_packs << pack
  puts "Processed rule pack #{pack}"
end

outfile = File.open(pack_rules_yaml, 'w')
outfile.puts packs.to_yaml
outfile.close
puts "\nWrote all YAML pack rules/associations to: #{pack_rules_yaml}"

outfile = File.open(pack_rules_list, 'w')
outfile.puts rule_packs
outfile.close
puts "Wrote list of pack rules to: #{pack_rules_list}"

FileUtils.rm_rf(rules_dir)

puts "\nComplete!\n"