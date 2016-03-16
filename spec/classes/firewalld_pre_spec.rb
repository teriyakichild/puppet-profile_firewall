require 'spec_helper'
describe 'profile_firewall::firewalld::pre' do
  context 'with defaults for all parameters' do
    let(:facts) { {
      :kernel                    => 'Linux',
      :operatingsystem           => 'RedHat',
      :operatingsystemrelease    => 7,
      :operatingsystemmajrelease => 7
    } }
    it { 
      should contain_firewalld_service('Allow access to ssh').with(
        'ensure'  => 'present',
        'zone'    => 'public',
        'service' => 'ssh'
      )
    }
  end
end
