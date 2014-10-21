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
  $ensure = running
) {

  case $ensure {
    /^(running|stopped)$/: {
      # valid ensure value
    }
    default: {
      fail("${title}: Ensure value '${ensure}' is not supported")
    }
  }

  class { 'firewall':
    ensure => $ensure
  }

  if $ensure == running {
    include 'profile_firewall::pre'
    include 'profile_firewall::post'

    resources { 'firewall':
      purge => true
    }

    Firewall {
      require => Class['profile_firewall::pre'],
      before  => Class['profile_firewall::post'],
    }

    firewall { '050 allow ssh':
      proto  => 'tcp',
      port   => '22',
      action => 'accept',
    }

    firewall { '950 allow zabbix':
      proto  => 'tcp',
      port   => '10050',
      action => 'accept',
    }
  }
}
