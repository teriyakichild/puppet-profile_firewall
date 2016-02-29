require 'ipaddr'

=begin
Takes up to 3 arguments:
 1. A string containing either 1 IP or 2 IP addresses separated by a hyphen and creates an array of the range of the two IPs.
 2. A string or integer containing the service or port number to be added.
 3. If a port is specified the a string with the protocol is also needed. We will default  to tcp to be safe.

*Range Example with a service:*

  firewall_parse_range('192.168.0.10-192.168.0.12', 'ssh')

Would result in:

  {"192.168.0.10 access to ssh"=>{"source"=>"192.168.0.10/32", "service"=>"ssh"}, "192.168.0.11 access to ssh"=>{"source"=>"192.168.0.11/32", "service"=>"ssh"}, "192.168.0.12 access to ssh"=>{"source"=>"192.168.0.12/32", "service"=>"ssh"}}

*Single IP:*

  firewall_parse_range('192.168.0.10', ssh)

Would result in:

  {"192.168.0.10 access to ssh"=>{"source"=>"192.168.0.10/32", "service"=>"ssh"}}

*Range Example with port and protocol:*

  firewall_parse_range('192.168.0.10-192.168.0.12', 8080, 'tcp')

Would result in:

  {"192.168.0.10 access to 8080"=>{"source"=>"192.168.0.10/32", "port"=>{"port"=>"8080", "protocol"=>"tcp"}}, "192.168.0.11 access to 8080"=>{"source"=>"192.168.0.11/32", "port"=>{"port"=>"8080", "protocol"=>"tcp"}}, "192.168.0.12 access to 8080"=>{"source"=>"192.168.0.12/32", "port"=>{"port"=>"8080", "protocol"=>"tcp"}}}

*Single IP:*

  firewall_parse_range('192.168.0.10', 8080, tcp)

Would result in:

  {"192.168.0.10 access to 8080"=>{"source"=>"192.168.0.10/32", "port"=>{"port"=>"8080", "protocol"=>"tcp"}}}
=end

module Puppet::Parser::Functions
  newfunction(:firewall_parse_range, :type => :rvalue) do |args|
    Puppet::Parser::Functions.function('generate_rules')

    src_range = args[0]
    service_port = args[1]
    protocol = args[2]
    
    if protocol.to_s == ''
      protocol = 'tcp'
    end
 
    ips = src_range.split('-')
    if ips.length == 2
      ip1 = ips[0]
      ip2 = ips[1]
      range = IPAddr.new(ip1)..IPAddr.new(ip2)
      ip_range = range.map(&:to_s)
      rules = function_generate_rules([ip_range, service_port, protocol])
      rules
    elsif ips.length == 1
      ip_range = ips
      rules = function_generate_rules([ip_range, service_port, protocol])
      rules
    else
      raise Puppet::ParseError, "Unexpected format for src or src_range"
    end
  end
end

