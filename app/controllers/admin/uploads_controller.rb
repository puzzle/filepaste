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

class Admin::UploadsController < ApplicationController
  before_filter :check_for_admin

  def check_for_admin
    unless session[:admin_group]
      render :inline => "no Access"
    end
  end


  # GET /admin/uploads/1
  # GET /admin/uploads/1.xml
  def show
    @upload = Upload.find(params[:id])

    respond_to do |format|
      format.html # show.html.erb
      format.xml  { render :xml => @upload }
    end
  end

  # GET /admin/uploads
  # GET /admin/uploads.xml
  def index
    @uploads = Upload.find(:all)

    respond_to do |format|
      format.html # index.html.erb
      format.xml  { render :xml => @uploads }
    end
  end

  # DELETE /admin/uploads/1
  # DELETE /admin/uploads/1.xml
  def destroy
    @upload = Upload.find(params[:id])

    dirname = File.join ::Rails.root.to_s, 'public', 'downloads', @upload.hash_key
    filepath = File.join dirname, @upload.filename
    
    File.delete filepath
    Dir.delete dirname
    @upload.destroy

    respond_to do |format|
      format.html { redirect_to(admin_uploads_url) }
      format.xml  { head :ok }
    end
  end

end
