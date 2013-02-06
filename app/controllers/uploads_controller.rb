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

class UploadsController < ApplicationController

  # GET /uploads/new
  # GET /uploads/new.xml
  def new
    @upload = Upload.new

    respond_to do |format|
      format.html # new.html.erb
      format.xml  { render :xml => @upload }
    end
  end

  # POST /uploads
  # POST /uploads.xml
  def create
    datafile = params[:uploads][:file]
   
    # Create a new hash
    chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
    hash_key = ""
    @filepaste_settings['general']['hash_length'].to_i.times do
      hash_key << chars[rand(chars.size)]
    end

    dirname = File.join ::Rails.root.to_s, 'public', 'downloads', hash_key
    filepath = File.join dirname, datafile.original_filename

    # Now we save the File to the disk
    Dir.mkdir dirname 
    File.open(filepath, "wb") { |file| file.write datafile.read }

    # Save the file information to the database
    @upload = Upload.new
    @upload.filename = datafile.original_filename
    @upload.description = params[:uploads][:description]
    @upload.hash_key = hash_key
    @upload.content_type = datafile.content_type
    @upload.updated_at = Time.now
    @upload.created_at = Time.now

    respond_to do |format|
      if @upload.save
        flash[:notice] = 'Upload was successfully created.'
        format.html { redirect_to( :action => 'downloadinfo', :id => hash_key ) }
        format.xml  { render :xml => @upload, :status => :created, :location => @upload }
      else
        format.html { render :action => "new" }
        format.xml  { render :xml => @upload.errors, :status => :unprocessable_entity }
      end
    end
  end

  def downloadinfo
    @upload = Upload.find(:first, :conditions => [ 'hash_key = ?', params[:id] ])
    if @upload.nil?
      respond_to do |format|
        flash[:notice] = 'No such file.'
        format.html { render :action => "new" }
      end
    end
  end
end
