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

class ApplicationController < ActionController::Base
  before_filter :load_settings, :authenticate

  helper :all # include all helpers, all the time

  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '87756b121176328abb8c413a7674af31'
  
  def load_settings
    @filepaste_settings = YAML.load( ERB.new( File.open( ::Rails.root.to_s + "/config/settings.yml" ).read ).result )
  end

  def authenticate
    authenticate_or_request_with_http_basic @filepaste_settings['general']['title'] do |username, password|
      ldap = Net::LDAP.new :host => @filepaste_settings['ldap']['host'],
                           :port => @filepaste_settings['ldap']['port'],
                           :base => @filepaste_settings['ldap']['base']

      begin
        bind_result = ldap.bind_as :filter   => "(uid=#{username})",
                                   :password => password
      rescue Net::LDAP::LdapError
        bind_result = false
      end

      # Lets have a look if the user is in the admin group
      ldap.search :filter => Net::LDAP::Filter.eq('memberUid', username),
                  :base => @filepaste_settings['ldap']['admin_group_dn'] do |entry|
        session[:admin_group] = true
      end

      bind_result
    end
  end

end
