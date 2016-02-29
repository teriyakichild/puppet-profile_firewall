module Puppet::Parser::Functions
  newfunction(:generate_rules, :type => :rvalue) do |args|
    ip_range = args[0]
    service_port = args[1]
    protocol = args[2]
 
    rules = Hash.new
    ip_range.each do |ip|
      rules[ip + " access to " + service_port] = Hash.new
      if ip.include? '/'
        suffix = ''
      else
        suffix = '/32'
      end
      rules[ip + " access to " + service_port]['source'] = ip+suffix
      begin
        if Integer(service_port)
          rules[ip + " access to " + service_port]['port'] = {'port' => service_port, 'protocol' => protocol}
        end
      rescue
        rules[ip + " access to " + service_port]['service'] = service_port
      end
    end
    return rules
  end
end

