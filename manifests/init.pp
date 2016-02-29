# == Class: profile_firewall
#
# This is a profile to manage iptables on a system using the
# puppetlabs-firewall module.  With this class, basic rules are added that only
# allow from icmp, allow from localhost, allow established/related connections,
# and allow ssh.  Everything else is denied.  Once you have pulled this class
# into your module, you can use the firewall { ... } resource to add your
# own rules.
#
# See https://forge.puppetlabs.com/puppetlabs/firewall for additional
# information around the firewall resource.
#
# === Parameters
#
# [*ensure*]
# String. This should be a value of <tt>running</tt> or <tt>stopped</tt>.
# If set to stopped, iptables is disabled. If set to running, iptables is
# enabled and basic rules are applied.
# Defaults to <tt>running</tt>
#
# === Variables
#
# None.
#
# === Examples
#
# * iptables running with basic rules
#
#  include profile_firewall
#
# * iptables stopped
#
# class { 'profile_firewall': ensure => stopped }
#
# === Authors
#
# Alex Schultz <alex.schultz@rackspace.com>
#
class profile_firewall (
  $ensure                = running,
  $ssh_src_range         = undef,
  $ssh_src               = undef,
  $ssh_src_desc_modifier = 'anyone',
) {

  case $ensure {
    /^(running|stopped)$/: {
      # valid ensure value
    }
    default: {
      fail("${title}: Ensure value '${ensure}' is not supported")
    }
  }

  if $ssh_src_range != undef {
    if $ssh_src != undef {
      fail('Can not set both ssh_src and ssh_src_range.')
    }
  }

  if $::operatingsystemmajrelease < 7 {
    class { 'firewall':
      ensure => $ensure
    }

    if $ensure == running {
      include 'profile_firewall::iptables::pre'
      include 'profile_firewall::iptables::post'

      resources { 'firewall':
        purge => true
      }

      Firewall {
        require => Class['profile_firewall::iptables::pre'],
        before  => Class['profile_firewall::iptables::post'],
      }

      firewall { "050 allow ssh access from ${ssh_src_desc_modifier}":
        proto     => 'tcp',
        src_range => $ssh_src_range,
        source    => $ssh_src,
        dport     => '22',
        action    => 'accept',
      }

      firewall { '950 allow zabbix':
        proto  => 'tcp',
        dport  => '10050',
        action => 'accept',
      }
    }
  } else {
    include 'firewalld'
    
    if $ensure == running {

      firewalld_zone { 'public':
        ensure           => 'present',
        #target          => '%%REJECT%%',
        purge_rich_rules => true,
        purge_services   => true,
        purge_ports      => true,
      }
      
      $service_rich_rule_defaults = {
        ensure => present,
        zone   => 'public',
        action => 'accept'
      }
      
      if $ssh_src_range != undef {
        create_resources(firewalld_rich_rule,
        firewall_parse_range($ssh_src_range,'ssh'), $service_rich_rule_defaults)
      } elsif $ssh_src != undef {
        create_resources(firewalld_rich_rule, firewall_parse_range($ssh_src,
        'ssh'), $service_rich_rule_defaults)
      } else {
        # If no ssh_src or ssh_src_range then open ssh for all
        firewalld_service { 'Allow access to ssh':
          ensure  => present,
          zone    => 'public',
          service => 'ssh',
        }
      }

      firewalld_port { 'allow zabbix':
        ensure   => present,
        zone     => 'public',
        protocol => 'tcp',
        port     => '10050',
      }
    }
  }
}
