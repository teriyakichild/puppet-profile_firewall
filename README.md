# profile_firewall

## Overview

This is a profile to manage a firewall on a system using the
puppetlabs-firewall module.  With this class, basic rules are added that only
allow from icmp, allow from localhost, allow established/related connections,
and allow ssh.  Everything else is denied.  Once you have pulled this class
into your module, you can use the firewall { ... } resource to add your
own rules.

## Dependancies

This module depends on [puppetlabs/firewall](https://forge.puppetlabs.com/puppetlabs/firewall) 

## Example

To get started, you'll want to simply include the class and then you can
create your own firewall resources.  

```
class myfirewall {
  include profile_firewall
  firewall { '100 allow http':
    proto  => 'tcp',
    port   => '80',
    action => 'accept',
  }
}
```
