# == Class: profile_firewall::post
#
# This is the profile_firewall post class. It contains rules to be applied last
# to iptables.
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
# include profile_itables::post
#
# === Authors
#
# Alex Schultz <alex.schultz@rackspace.com>
#
class profile_firewall::post {
  # reject everything else
  firewall { '999 deny all':
    proto  => 'all',
    action => 'reject',
    reject => 'icmp-host-prohibited',
    before => undef
  }
}
