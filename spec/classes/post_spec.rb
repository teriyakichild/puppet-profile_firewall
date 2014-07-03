require 'spec_helper'
describe 'profile_firewall::post' do


  context 'with defaults for all parameters' do
    let(:facts) { {
      :kernel                 => 'Linux',
      :operatingsystem        => 'RedHat',
      :operatingsystemrelease => 6
    } }
    it { 
      should contain_firewall('999 deny all').with(
        'proto'   => 'all',
        'action'  => 'reject')
    }
  end
end
