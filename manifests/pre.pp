# == Class: profile_firewall::pre
#
# This is the profile_firewall pre class. It contains rules to be applied first 
# to iptables.
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
# include profile_firewall::pre
#
# === Authors
#
# Alex Schultz <alex.schultz@rackspace.com>
#
class profile_firewall::pre {
  require 'firewall'

  Firewall {
    require => undef,
  }

  # default rules
  firewall { '000 accept all icmp':
    proto  => 'icmp',
    action => 'accept'
  }->
  firewall { '001 accept all on lo':
    proto   => 'all',
    iniface => 'lo',
    action  => 'accept'
  }->
  firewall { '002 accept related and established':
    proto   => 'all',
    ctstate => ['RELATED', 'ESTABLISHED'],
    action  => 'accept'
  }
}
