#!/usr/bin/env ruby

require 'cgi'
require 'open-uri'
require 'uri'

require 'rubygems'
require 'nokogiri'

NUM_MUDS = 10

class String

    def to_sql_literal
        "'" + self.gsub("'", "''") + "'"
    end

end

def get_mud_details(url)
    details = {}
    $stderr.puts "Getting MUD details at \"#{url}\" URL."
    doc = Nokogiri::HTML(open(url))

    doc.xpath("//a").each do |a_el|
        next unless a_el["href"] =~ %r|^https?://|
        url = URI(a_el["href"])
        next unless url.path =~ %r|/telnet\.cgi$|
        params = CGI::parse(url.query)
        telnet_url_param = params["url"].first
        telnet_url = URI(telnet_url_param)
        details[:host] = telnet_url.host
        details[:port] = telnet_url.port
        details[:url] = "telnet://" + details[:host] + ":" + details[:port].to_s + "/"
    end
    raise "Could not find MUD connection details at \"#{url}\" URL" unless details.has_key?(:host)

    doc.xpath("//div[@class='panel']").each do |panel_el|
        desc = panel_el.inner_text.gsub(/\s+/m, " ").strip
        details[:desc] = desc
    end

    details
end

def to_prefix(s)
    to_token_fn = Proc.new do |tok|
        tok.gsub(/er$/, "r")[0...5]
    end

    result = s
        .gsub(/[-_]/, " ")
        .gsub(/(\d+)(\S)/, "\\1 \\2")
        .gsub(/(\S)(\d+)/, "\\1 \\2")
        .gsub(/([a-z])([A-Z])/, "\\1 \\2")
        .gsub(/([A-Z]{2,})([a-z])/, "\\1 \\2")
        .downcase
        .gsub(/\b((the)|(is)|(of)|(a)|(and))\b/, "")
        .gsub(/[,]/, " ")
        .gsub(/[']/, "")
        .gsub(/\s+/m, " ")
        .gsub(/([^:]+):(.*)/, "\\1")
        .strip
        .to_s
    result = result
        .gsub(" ", "-")
        .gsub(/-(\d+)/, "\\1")
        .gsub(/(\d+)-/, "\\1")
        to_s
    result = "tc-" + result.split("-")[0...2].map { |w| to_token_fn.call(w) }.join("-")
    #$stderr.puts "Converted #{s.inspect} to #{result.inspect} prefix."
    result
end

def test_to_prefix
    raise unless to_prefix("Foo") == "tc-foo"

    raise unless to_prefix("3Foo") == "tc-3foo"
    raise unless to_prefix("3-Foo") == "tc-3foo"
    raise unless to_prefix("3 Foo") == "tc-3foo"
    raise unless to_prefix("3   Foo") == "tc-3foo"

    raise unless to_prefix("Foo3") == "tc-foo3"
    raise unless to_prefix("Foo_3") == "tc-foo3"
    raise unless to_prefix("Foo 3") == "tc-foo3"
    raise unless to_prefix("Foo\t3") == "tc-foo3"

    raise unless to_prefix("Foo 3 Bar") == "tc-foo3b"
    raise unless to_prefix("Foo\t3 bar") == "tc-foo3b"

    raise unless to_prefix("FooMUD") == "tc-foo-mud"
    raise unless to_prefix("Dark, and Stormy") == "tc-dark-storm"
    raise unless to_prefix("FooBar's: Long Subtitle") == "tc-foo-bars"
    raise unless to_prefix("This is THE Place") == "tc-this-place"
    raise unless to_prefix("Super Long MUD Name That Goes Onwardinthisway Forever") == "tc-supr-long"
end

test_to_prefix
url = "http://www.mudconnect.com/cgi-bin/all_rankings.cgi"
doc = Nokogiri::HTML(open(url))
i = 0
doc.xpath("//table[@id='all_rank_table']").each do |table_el|
    table_el.xpath(".//tr").each do |tr_el|
        next if tr_el.at_xpath(".//th")  # skip the header row
        tr_el.xpath(".//a").each do |a_el|
            next unless a_el["href"] =~ %r|^/mud-bin/adv_search\.cgi\?|
            tmc_mud_url = a_el["href"]
            tmc_mud_url = "http://www.mudconnect.com#{tmc_mud_url}" unless tmc_mud_url =~ %r|^https?://|
            details = get_mud_details(tmc_mud_url)
            details[:name] = a_el.inner_text
            details[:group_prefix] = to_prefix(details[:name])
            $stderr.puts "Found MUD w/ #{details.inspect} details."

            sql = "INSERT INTO `tc_worlds` (`name`, `group_prefix`, `url`, `desc`) VALUES ("
            sql += [
                details[:name].to_sql_literal,
                details[:group_prefix].to_sql_literal,
                details[:url].to_sql_literal,
                details[:desc].to_sql_literal,
            ].join(", ")
            sql += ");"
            puts sql

            i += 1
            exit(0) if i >= NUM_MUDS
        end
    end
end

