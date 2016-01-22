# Testing of Module

## Requirements
* See Gemfile

== Running Tests
```
git clone git@github.com/org/puppet-module.git
cd puppet-module
bundle install
bundle exec rake spec
```

To verify if your changes are indeed included when you run spec tests, you can run this:
```
bundle exec rake spec_clean spec_prep
```
This will download the fixtures in the ```spec/fixtures/modules``` directory. In that
directory, there should be a subdirectory per module. Double check and see if your
changes are indeed in the directories.