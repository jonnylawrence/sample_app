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
    uri = URI.parse("https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize")
      request = Net::HTTP::Get.new(uri)
      request["post_logout_redirect_uri"] = root_url

    req_options = {
    use_ssl: uri.scheme == "https",
    }

    response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
    http.request(request)

    puts 'sc: redirecting **********************'
    end


    

    redirect_to root_url
  end
end