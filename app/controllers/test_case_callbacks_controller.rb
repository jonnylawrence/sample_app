class TestCaseCallbacksController < ApplicationController
  require 'jwt'
  require 'json'
  layout 'popup'
  #protect_from_forgery with: :null_session
  skip_before_action :verify_authenticity_token
  #before_action :reject_csrf

  def show

    puts "********show start*******"
    puts params[:LoA]
    puts '-----------'
    puts params[:id_token] 
    puts "***************"

    @b2cjwt_pass = check_token if params[:id_token].present?

    puts "**** logged_in true or false **********" 
    puts logged_in?
    if logged_in? == false 
    
        puts '*********************** callback *******************'
        if params[:state].to_s.nil?
          puts "Params empty! setting state"
          params[:state]=SecureRandom.hex(16)
        else
          puts "Params NOT empty"
          puts "Param state from packet:"+params[:state].to_s
        end

        puts "Request path:"+request.path
        puts "URI Referer:"+URI(request.referer).path
        puts "Request.env":request.env["HTTP_REFERER"]
        #pp=CGI::parse(URI(request.referer).path)
        #if PP["p"] = "B2C_1A_Bupa-Uni-uat-SignInSignUp" then

        ########################################################
        # call back for reset password
        ########################################################
        uri_ref=URI(request.referer).path
        if (uri_ref =~ /forgotPassword/)
            puts '*********************** forgotten password *******************'
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

         if ( request.path =~ /maintainsecurity/)
          puts '*********************** maintainsecurity *******************'
          check_token
        end

        if jwthost # id jwthost is defined above
          puts "-----JWTHOST--------" + jwthost
        
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
          puts 'session variables****************'
          puts "ID>"
          puts session[:client_id] 
          puts "STATE>"
          puts session[:state]
          puts "NONCE>" 
          puts session[:nonce]
          puts "token>"
          puts session[:token]      
          puts "session end*************************"
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
    puts "********checking token *******"
    puts params[:LoA]
    puts '--------token below-----'
    puts params[:id_token]
    puts "******************************"
    # check body for a L2 Token, although token needs to be checked below
    if (params[:LoA] == "L1")       
      puts '*********** checking ID token....'
      @b2cjwt=Decode.new(params[:id_token],Rails.application.secrets.BC2_Assertion_secret)
      @b2cjwt.decode_segments
      puts @b2cjwt.header
      @sts = @b2cjwt.payload.to_json
      parsed = JSON.parse(@sts)
      jwtemail=parsed["email"].downcase
      
      #
      # Need to check signature on token !!!!!!!!!!!!!! NOT DONE
      #
      puts '>>>>>>>>>TOKEN OUTPUT START<<<<<<<<<<<<<'
      puts "LOA> " + parsed["LoA"]
      puts "email> " + jwtemail
      puts "iss> " + parsed["iss"]
      puts "OID> " + parsed["oid"]
      puts "exp> " + Time.at(parsed["exp"]).to_s
      puts "nbf> " + Time.at(parsed["nbf"]).to_s
      puts "aud> " + parsed["aud"]
      puts "acr> " + parsed["acr"]
      puts "nonce> " + parsed["nonce"]
      puts "iat> " + Time.at(parsed["iat"]).to_s
      puts "auth_time> " + Time.at(parsed["auth_time"]).to_s
      puts "rpName> " + parsed["rpName"]
      puts "ServiceHints> " + parsed["ServiceHints"]
      puts '>>>>>>>>>TOKEN OUTPUT END<<<<<<<<<<<<<'

      if (parsed["LoA"] == "L1")
        user = User.find_by(email: jwtemail)
          if user 
            puts '*********************** Logged in as level 2 *******************'
            log_in user # session_helper
           session[:jwttokenexp]=parsed["exp"]
           session[:jwttokennbf]=parsed["nbf"]
            session[:jwttokeniss]=parsed["iss"]
            session[:jwttokeniat]=parsed["iat"]
            session[:jwttokenauth_time]=parsed["auth_time"]
            session[:jwttokenemail]=jwtemail
            puts '<<<<<<<<<EMAIL CHECK>>'
            puts session[:jwttokenemail]
            session[:jwttokenloa]=parsed["LoA"]
            session[:jwttokenoid]=parsed["oid"]
            session[:jwttokenrpname]=parsed["rpName"]
            session[:jwttokenaud]=parsed["aud"]
            session[:jwttokenacr]=parsed["acr"] 
            session[:jwttokennonce]=parsed["nonce"]   
            #params[:session][:remember_me] == '1' ? remember(user) : forget(user)
            session[:b2clogin]=true
            redirect_to root_path and return
          else # local email not found - do signup
            do_signup
          end
      end   
    else # no LoA therefore not logged in
      puts '>>>>>>>>>>>INSIDE TOKEN CHECK BUT NOT LOGGED IN<<<<<<<<<<<<<<<<<<<<'
      session[:b2clogin]=false
    end # end params
  end # end def

  def not_logged_in
    puts '>>>>>>>>>>>>>>>>>NOT LOGGED IN<<<<<<<<<<<<<<<<<<<<'
      session[:b2clogin]=false
      redirect_to root_path and return
  end

  def do_signup
    puts '>>>>>>>>>>>>b2C USER NEEDS SIGN UP>>>>>>>>>>>>'
    session[:b2clogin]=true
    redirect_to signup_path
  end

end # end class
