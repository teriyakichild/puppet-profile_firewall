require 'spec_helper'
describe 'profile_firewall' do
  let(:facts) { {
    :kernel                 => 'Linux',
    :operatingsystem        => 'RedHat',
    :operatingsystemrelease => '6'
  } }


  context 'with defaults for all parameters' do
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
      should contain_firewall('050 allow ssh access from anyone').with(
        'proto'   => 'tcp',
        'port'    => '22',
        'action'  => 'accept')
      should contain_firewall('950 allow zabbix').with(
        'proto'   => 'tcp',
        'port'    => '10050',
        'action'  => 'accept')
      should contain_firewall('999 deny all').with(
        'proto'   => 'all',
        'action'  => 'reject')
    }
  end

  context 'with ssh_src set to 10.0.0.0/8' do
    let(:params) do
    {
      :ssh_src               => '10.0.0.0/8',
      :ssh_src_desc_modifier => 'some place',
    }
    end
    it {
      should contain_class('profile_firewall')
      should contain_firewall('050 allow ssh access from some place').with(
        'proto'  => 'tcp',
        'port'   => '22',
        'source' => '10.0.0.0/8',
        'action' => 'accept')
    }
  end

  context 'with ssh_src_range set to 10.0.0.0-10.0.0.1' do
    let(:params) do
    {
      :ssh_src_range         => '10.0.0.0-10.0.0.1',
      :ssh_src_desc_modifier => 'some place',
    }
    end
    it {
      should contain_class('profile_firewall')
      should contain_firewall('050 allow ssh access from some place').with(
        'proto'     => 'tcp',
        'port'      => '22',
        'src_range' => '10.0.0.0-10.0.0.1',
        'action'    => 'accept')
    }
  end

end
