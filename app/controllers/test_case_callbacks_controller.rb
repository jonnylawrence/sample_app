class TestCaseCallbacksController < ApplicationController
  require 'jwt'
  require 'json'
  layout 'popup'
  #protect_from_forgery with: :null_session
  #skip_before_action :verify_authenticity_token
  #before_action :reject_csrf

  def show
    sailLoA = Sail.get("LoA")
    # puts 'tccbc: -------------------------'
    # puts session[:b2clogin]
    # do_signup if session[:b2clogin]==true

    puts "tccbc:********show start*******"
    puts params[:LoA]
    puts 'tccbc:----------checking token if the value below is present-------'
    puts params[:id_token] 
    puts '-----------------------'
    puts "Request path:"+request.path unless request.path.nil?
    puts "URI Referer:"+URI(request.referer).path unless URI(request.referer).path.nil?
    puts "Request.env:"+request.env["HTTP_REFERER"] unless request.env["HTTP_REFERER"].nil?
    puts "tccbc:***************"

    @b2cjwt_pass = check_token if params[:id_token].present?

    puts "tccbc:**** logged_in true or false **********" 
    puts logged_in?

    if logged_in? == false 
    
        puts 'tccbc:*********************** callback *******************'
        if params[:state].to_s.nil?
          puts "Params empty! setting state"
          params[:state]=SecureRandom.hex(16)
        else
          puts "Params NOT empty"
          puts "Param state from packet:"+params[:state].to_s
        end

        puts "tccbc:Request path:"+request.path unless request.path.nil?
        puts "tccbc:URI Referer:"+URI(request.referer).path unless URI(request.referer).path.nil?
        puts "tccbc:Request.env:"+request.env["HTTP_REFERER"] unless request.env["HTTP_REFERER"].nil?
    
        ########################################################
        # call back for reset password
        ########################################################
        uri_ref=URI(request.referer).path
        if (uri_ref =~ /forgotPassword/)
            puts 'tccbc:*********************** forgotten password *******************'
            jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
            jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize"
            jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize"
        end

        if ( request.path =~ /forgotusername/)
          puts '*********************** forgotten username *******************'
          jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
          jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-emailrecovery/oauth2/v2.0/authorize"
          jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-emailrecovery/oauth2/v2.0/authorize"
        end

        if jwthost # id jwthost is defined above
          puts "tccbc:-----JWTHOST--------" + jwthost
        
          client = OpenIDConnect::Client.new(
            identifier: Rails.application.secrets.B2C_client_id,
            secret: Rails.application.secrets.B2C_client_secret,
            redirect_uri: jwtredirect_uri,
            host: jwthost,
            authorization_endpoint: jwtauthorization_endpoint
          )

          #session[:client_id] = Rails.application.secrets.B2C_client_id
          #session[:state] = SecureRandom.hex(16)
          session[:nonce] = SecureRandom.hex(16)      
          puts 'tccbc:session variables****************'
          puts "ID>"
          puts session[:client_id] 
          puts "STATE>"
          puts session[:state]
          puts "NONCE>" 
          puts session[:nonce]
          puts "token>"
          puts session[:token]      
          puts "tccbc:session end*************************"
          redirect_to client.authorization_uri(
            state: params[:state], # params[:state] should equal original session[:state]
            nonce: session[:nonce], # new nonce
            scope: "openid profile",
            response_type: "id_token",
            response_mode: "form_post",
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: session[:token], # original token request
            ui_locales: "en-GB",
            prompt: "login"
            ) and return            
          else
            not_logged_in
          end # end of jwthost check
    
    else # logged in but needing some action potentially
        
      puts 'tccbc: logged in but may need some action like elevation'

        if ( request.path =~ /signinl3/) || ( request.path =~ /signinl2/) 
          puts 'tccbc:*********************** forgotten username *******************'
          jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
          jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize"
          jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize"
          jwtloa="L3" if ( request.path =~ /signinl3/)
          jwtloa="L2" if ( request.path =~ /signinl2/)
       
          client = OpenIDConnect::Client.new(
            identifier: Rails.application.secrets.B2C_client_id,
            secret: Rails.application.secrets.B2C_client_secret,
            redirect_uri: jwtredirect_uri,
            host: jwthost,
            authorization_endpoint: jwtauthorization_endpoint
          )
        
            session[:client_id] = Rails.application.secrets.B2C_client_id
            session[:state] = SecureRandom.hex(16)
            session[:nonce] = SecureRandom.hex(16)
            
          # add client assertion payload, needs signing with assertion key
          # https://github.com/jwt/ruby-jwt
      
          expirey_time = 24.hours.from_now.to_i
          time_now = Time.now.to_i
          payload = { 
            LoALevelRequest: jwtloa, 
            iss: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize',
            aud: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
            exp: expirey_time,
            iat: time_now,
            nbf: time_now
          }

          token = JWT.encode payload, Rails.application.secrets.BC2_Assertion_secret, 'HS256'
          session[:token] = token
          
          redirect_to client.authorization_uri(
            state: session[:state],
            nonce: session[:nonce],
            scope: "openid profile",
            response_type: "id_token",
            response_mode: "form_post",
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: token,
            ui_locales: "en-GB",
            prompt: "login"
          )
        end

    end     # end if logged_in
  end # end def
  

private

  def reject_csrf
    unless params[:state] == session[:state]
      render text: 'CSRF Attack Detected'
    end
  end

  def check_token
    ########################################################
    # after returning from B2C check the presence of a token 
    ########################################################
    puts 'tccbc; *************** printing cookies ***********'
    cookies.each do |cookie|
      puts cookie
    end
    puts "tccbc:********checking token *******"
    puts params[:LoA]
    puts '--------token below-----'
    puts params[:id_token]
    puts "tccbc:******************************"
    # check body for a L2 Token, although token needs to be checked below
    if (params[:LoA] == "L1") || (params[:LoA] == "L2")  || (params[:LoA] == "L3")  
      puts '*********** checking ID token....'
      @b2cjwt=Decode.new(params[:id_token],Rails.application.secrets.BC2_Assertion_secret)
      @b2cjwt.decode_segments
      puts @b2cjwt.header
      @sts = @b2cjwt.payload.to_json
      parsed = JSON.parse(@sts)
      jwtemail=parsed["email"].downcase
      jwtoid=parsed["oid"]
      jwtmobile=parsed["mobile"]
      
      #
      # Need to check signature on token !!!!!!!!!!!!!! NOT DONE
      #
      puts 'tccbc:>>>>>>>>>TOKEN OUTPUT START<<<<<<<<<<<<<'
      puts "LOA> " + parsed["LoA"]
      puts "email> " + jwtemail
      puts "iss> " + parsed["iss"]
      puts "OID> " + jwtoid
      puts "mobile" + jwtmobile unless jwtmobile.nil?
      puts "exp> " + Time.at(parsed["exp"]).to_s
      puts "nbf> " + Time.at(parsed["nbf"]).to_s
      puts "aud> " + parsed["aud"]
      puts "acr> " + parsed["acr"]
      puts "nonce> " + parsed["nonce"]
      puts "iat> " + Time.at(parsed["iat"]).to_s
      puts "auth_time> " + Time.at(parsed["auth_time"]).to_s
      puts "rpName> " + parsed["rpName"]
      puts "ServiceHints> " + parsed["ServiceHints"]
      puts 'tccbc:>>>>>>>>>TOKEN OUTPUT END<<<<<<<<<<<<<'

      
      if (parsed["LoA"] == "L1") || (params[:LoA] == "L2") || (params[:LoA] == "L3")  
        user = User.find_by(email: jwtemail)
          if user 
            puts 'tccbc:*********************** Logged in as' + parsed["LoA"] + '**********'
           log_in user # session_helper
           session[:jwttokenexp]=parsed["exp"]
           session[:jwttokennbf]=parsed["nbf"]
            session[:jwttokeniss]=parsed["iss"]
            session[:jwttokeniat]=parsed["iat"]
            session[:jwttokenauth_time]=parsed["auth_time"]
            session[:jwttokenemail]=jwtemail
            session[:jwttokenmobile]=jwtmobile unless jtwmobile.nil?
            session[:jwttokenloa]=parsed["LoA"]
            session[:jwttokenoid]=jwtoid
            session[:jwttokenrpname]=parsed["rpName"]
            session[:jwttokenaud]=parsed["aud"]
            session[:jwttokenacr]=parsed["acr"] 
            session[:jwttokennonce]=parsed["nonce"]   
            #params[:session][:remember_me] == '1' ? remember(user) : forget(user)
            session[:b2clogin]=true
            redirect_to root_path and return
          else
            puts 'tccbc:>>>>>>>>>>>>b2C USER NEEDS SIGN UP - CREATING DUMMY RECORD >>>>>>>>>>>>'
            @user = User.new(:name => "Please complete",:member => "Please complete", :email => "dummy@dummy.com", :password => "0racle", :password_confirmation => "0racle")
            if @user.save 
              log_in @user
              session[:b2clogin]=true
              session[:jwttokenexp]=parsed["exp"]
           session[:jwttokennbf]=parsed["nbf"]
            session[:jwttokeniss]=parsed["iss"]
            session[:jwttokeniat]=parsed["iat"]
            session[:jwttokenauth_time]=parsed["auth_time"]
            session[:jwttokenemail]=jwtemail
            puts 'tccbc:<<<<<<<<<EMAIL CHECK>>'
            puts session[:jwttokenemail]
            session[:jwttokenloa]=parsed["LoA"]
            session[:jwttokenoid]=parsed["oid"]
            session[:jwttokenrpname]=parsed["rpName"]
            session[:jwttokenaud]=parsed["aud"]
            session[:jwttokenacr]=parsed["acr"] 
            session[:jwttokennonce]=parsed["nonce"]  
              redirect_to signup_path, email: jwtemail and return
            else
              puts 'tccbc:**** create a dummy user record for registration failed ***'
            end 
          end
      end   
    else # no LoA therefore not logged in
      puts 'tccbc:>>>>>>>>>>>INSIDE TOKEN CHECK BUT NOT LOGGED IN<<<<<<<<<<<<<<<<<<<<'
      session[:b2clogin]=false
    end # end params
  end # end def

  def not_logged_in
    puts 'tccbc:>>>>>>>>>>>>>>>>>NOT LOGGED IN<<<<<<<<<<<<<<<<<<<<'
      session[:b2clogin]=false
      redirect_to root_path and return
  end
end # end class
