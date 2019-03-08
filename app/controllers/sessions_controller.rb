class SessionsController < ApplicationController
  require 'net/http'
  require 'uri'
  require 'json'
  
  def new
  end

  def create
    user = User.find_by(email: params[:session][:email].downcase)
    if user && user.authenticate(params[:session][:password])
      log_in user
      params[:session][:remember_me] == '1' ? remember(user) : forget(user)
      redirect_back_or user
    else
      flash.now[:danger] = 'Invalid email/password combination'
      render 'new'
    end
  end

  def destroy

    puts 'sc: local logout ********************'
    log_out
    puts 'sc: sending logout to b2c ***********'

      state= SecureRandom.hex(16)
      created_uri= add_params("https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/logout",
      post_logout_redirect_uri: "https://b2c-ruby.herokuapp.com/", state: state )
      puts "sc: created uri : " + created_uri
      uri = URI.parse(created_uri)
  
      request = Net::HTTP::Get.new(uri)
      req_options = {
        use_ssl: uri.scheme == "https",
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
        end
    
      puts 'sc: response"'
      puts response.code
      puts response.body
      puts 'sc: redirecting **********************'
  end
    #redirect_to root_url
  
    private
  
    def add_params(url, params = {})
      uri = URI(url)
      params    = Hash[URI.decode_www_form(uri.query || '')].merge(params)
      uri.query =      URI.encode_www_form(params)
      uri.to_s
    end
end