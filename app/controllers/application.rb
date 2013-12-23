# Copyright (C) 2008 Andreas Zuber 
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'net/ldap'

class ApplicationController < ActionController::Base
  before_filter :load_settings, :authenticate

  helper :all # include all helpers, all the time

  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '87756b121176328abb8c413a7674af31'
  
  def load_settings
    @filepaste_settings = YAML.load( File.open( RAILS_ROOT + "/config/settings.yml" ) )
  end

  def authenticate
    authenticate_or_request_with_http_basic @filepaste_settings['general']['title'] do |username, password|
      ldap_config = {:host => @filepaste_settings['ldap']['host'],
                     :port => @filepaste_settings['ldap']['port'],
                     :base => @filepaste_settings['ldap']['base']}
      # set initial bind user, required if searching for the final bind user already requires auth
      if @filepaste_settings['ldap']['bind_user']
        ldap_config[:auth] = {:method => :simple,
                              :username => @filepaste_settings['ldap']['bind_user'],
                              :password => @filepaste_settings['ldap']['bind_password']}
      end
      ldap = Net::LDAP.new(ldap_config)

      begin
        username_attribute = @filepaste_settings['ldap']['username_attribute'] || 'uid'
        bind_result = ldap.bind_as :filter   => Net::LDAP::Filter.eq(username_attribute, username),
                                   :password => password
      rescue Net::LDAP::LdapError
        bind_result = false
      end

      # Lets have a look if the user is in the admin group
      groupmember_attribute = @filepaste_settings['ldap']['groupmember_attribute'] || 'memberUid'
      if @filepaste_settings['ldap']['groupmember_full_dn']
        ldap.search :filter => Net::LDAP::Filter.eq(username_attribute, username),
                    :attributes => ['dn'] do |entry|
          user = entry.dn
        end
      else
        user = username
      end
      ldap.search :filter => Net::LDAP::Filter.eq(groupmember_attribute, user),
                  :base => @filepaste_settings['ldap']['admin_group_dn'] do |entry|
        session[:admin_group] = true
      end

      bind_result
    end
  end

end
