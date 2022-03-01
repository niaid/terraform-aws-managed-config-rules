#!/usr/bin/env ruby

require 'json'
require 'yaml'
require 'nokogiri'
require 'open-uri'

# Rules that we have, but are named differently than AWS (we use the identifier)
renamed_rules = [
  "cloudtrail-enabled",
  "ec2-instance-managed-by-systems-manager",
  "ec2-instances-in-vpc",
  "multi-region-cloudtrail-enabled",
  "restricted-common-ports",
  "restricted-ssh",
]

url       = 'https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html'
html      = URI.open(url)
doc       = Nokogiri::HTML(html)
aws_rules = []

doc.css("li").each do |item|
  aws_rules << item.text
end

init      = `terraform init`
keys      = `echo "keys((local.managed_rules))" | terraform console`
our_rules = JSON.parse("#{keys[0..-5]}]")

our_rules.concat(renamed_rules)

aws_rules.each do |aws_rule|
  if !our_rules.include?(aws_rule)
    puts aws_rule
  end
end