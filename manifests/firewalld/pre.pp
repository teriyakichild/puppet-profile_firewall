# == Class: profile_firewall::iptables::pre
#
# This is the profile_firewall firewaldl pre class. 
# It contains rules to be applied first to iptables.
#
#
# === Parameters
#
# None.
#
# === Variables
#
# None.
#
# === Examples
#
# include profile_firewall::firewalld::pre
#
#
class profile_firewall::firewalld::pre {

  Firewall {
    require => undef,
  }

  # Allowing ssh connections
  $service_rich_rule_defaults = {
    ensure => present,
    zone   => 'public',
    action => 'accept'
  }
  
  if $profile_firewall::ssh_src_range != undef {
    create_resources(
      firewalld_rich_rule,
      firewall_parse_range($profile_firewall::ssh_src_range,'ssh'), 
      $service_rich_rule_defaults
    )
  } elsif $profile_firewall::ssh_src != undef {
    create_resources(
      firewalld_rich_rule,
      firewall_parse_range($profile_firewall::ssh_src, 'ssh'),
      $service_rich_rule_defaults
    )
  } else {
    # If no ssh_src or ssh_src_range then open ssh for all
    firewalld_service { 'Allow access to ssh':
      ensure  => present,
      zone    => 'public',
      service => 'ssh',
    }
  }
}
