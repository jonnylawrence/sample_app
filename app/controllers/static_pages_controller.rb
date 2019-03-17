class StaticPagesController < ApplicationController
  require 'jwt'
  require 'json'
  require 'net/http'
  require 'uri'
  require 'json/jwt'

  def home  
    puts '****in home static pages controller******'

    puts '<<<<starting thread to discovery IDP>>>>'
    t1 = Thread.new{discovery_idp()}

    if logged_in? 
      @micropost  = current_user.microposts.build
      @feed_items = current_user.feed.paginate(page: params[:page])
    end

    @b2clogin='b2c-rp-response_type-code'
  end

  def help
  end

  def elevate
   
  end

  def confidential
    unless session[:jwttokenloa] == "L3"
      puts '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ setting redirect = confidential '
      session[:redirect] = "confidential"
      render 'elevate'
    end
  end

  private

  def discovery_idp

  if !session[:b2ckid]
    puts 'spc: threaded.....getting kid from B2C OID discovery endpoint for keys....'
    uri = URI.parse("https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1a_bupa-uni-uat-signinsignup")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    parsed = JSON.parse(response.body)
    session[:b2ckid]=parsed["keys"][0]["kid"]
    session[:b2cn]=parsed["keys"][0]["n"]
    session[:b2ce]=parsed["keys"][0]["e"]
    session[:b2calg]=parsed["keys"][0]["kty"]
    put "spc: kid set>" + session[:b2ckid] unless session[:b2ckid].nil?
   end

  end

end
