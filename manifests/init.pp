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

  validate_re($ensure, ['^running|stopped',])

  if ($ssh_src_range) and ($ssh_src) {
    fail('Can not set both ssh_src and ssh_src_range.')
  }

  if $::operatingsystemmajrelease == undef {
    $release = $::lsbmajdistrelease
  } else {
    $release = $::operatingsystemmajrelease
  }
  if $release == undef {
    fail('This system doesnt have the facts lsbmajdistrelease or operatingsystemmajrelease')
  }

  if ($release + 0) < 7 {
    class { 'firewall':
      ensure => $ensure
    }

    if $ensure == running {
      include '::profile_firewall::iptables::pre'
      include '::profile_firewall::iptables::post'

      resources { 'firewall':
        purge => true,
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

    include ::firewalld

    if $ensure == running {
      include '::profile_firewall::firewalld::pre'

      firewalld_zone { 'public':
        ensure           => 'present',
        purge_rich_rules => true,
        purge_services   => true,
        purge_ports      => true,
      }

      Firewalld {
        require => Class['profile_firewall::firewalld::pre'],
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
