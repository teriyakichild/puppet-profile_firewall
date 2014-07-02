require 'spec_helper'
describe 'profile_firewall' do


  context 'with defaults for all parameters' do
    let(:facts) { {
      :kernel                 => 'Linux',
      :operatingsystem        => 'RedHat',
      :operatingsystemrelease => 6
    } }
    it { 
      should contain_class('profile_firewall') 
      should contain_firewall('000 accept all icmp').with(
        'proto'  => 'icmp',
        'action' => 'accept')
      should contain_firewall('001 accept all on lo').with(
        'proto'   => 'all',
        'iniface' => 'lo',
        'action'  => 'accept')
      should contain_firewall('002 accept related and established').with(
        'proto'   => 'all',
        'ctstate' => ['RELATED', 'ESTABLISHED'],
        'action'  => 'accept')
      should contain_firewall('050 allow ssh').with(
        'proto'   => 'tcp',
        'port'    => '22',
        'action'  => 'accept')
      should contain_firewall('999 drop all').with(
        'proto'   => 'all',
        'action'  => 'drop')
    }
  end
end
