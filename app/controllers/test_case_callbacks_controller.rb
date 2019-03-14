class TestCaseCallbacksController < ApplicationController
  require 'jwt'
  require 'json'
  layout 'popup'
  #protect_from_forgery with: :null_session
  skip_before_action :verify_authenticity_token
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

        # for aggreate profile management page

        # if ( request.path =~ /maintainmobile/)
        #   puts '*********************** maintain mobile *******************'
        #   jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
        #   jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainmobilenumber/oauth2/v2.0/authorize"
        #   jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainmobilenumber/oauth2/v2.0/authorize"
        # end

        # if ( request.path =~ /changeusername/)
        #   puts '*********************** update username *******************'
        #   jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
        #   jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-updateuseremail/oauth2/v2.0/authorize"
        #   jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-updateuseremail/oauth2/v2.0/authorize"
        # end

        # if ( request.path =~ /changepassword/)
        #   puts '*********************** change password *******************'
        #   jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
        #   jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize"
        #   jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize"
        # end

        # if ( request.path =~ /maintainquestions/)
        #   puts '*********************** maintain security questions *******************'
        #   jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
        #   jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainsecurityquestions/oauth2/v2.0/authorize"
        #   jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainsecurityquestions/oauth2/v2.0/authorize"
        # end



        # if ( request.path =~ /deleteaccount/)
        #   puts '*********************** forgotten username *******************'
        #   jwtredirect_uri="https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code"
        #   jwthost="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-emailrecovery/oauth2/v2.0/authorize"
        #   jwtauthorization_endpoint="https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-emailrecovery/oauth2/v2.0/authorize"
        # end

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
      puts "tccbc:Request path:"+request.path unless request.path.nil?
      puts "tccbc:URI Referer:"+URI(request.referer).path unless URI(request.referer).path.nil?
      puts "tccbc:Request.env:"+request.env["HTTP_REFERER"] unless request.env["HTTP_REFERER"].nil?

        if ( URI(request.referer).path.downcase =~ /cancelled/)
          puts '>>>>>>  action cancelled, try a redirect to root'
          redirect_to root_path and return
        end

        if ( URI(request.referer).path.downcase =~ /deleteaccount/)
          puts '>>>>>>  deleting account, logging out and then redirect to root'
          User.find_by(oid:  session[:jwttokenoid]).destroy
          log_out
          redirect_to root_path and return
        end

       # if ( URI(request.referer).path.downcase =~ /maintainmobilenumber\/api\/phonefactor\/confirmed/)
        if ( URI(request.referer).path.downcase =~ /maintainmobilenumber/) && ( request.path !~ /signin/)
          puts '>>>>>>  maintain mobile or mobile phone changed, redirect to root'
          redirect_to root_path and return
        end

        

        if ( request.path =~ /changeusername/)
          puts '*********************** this is profile menu clicking on update username, redirecting *******************'
          redirect_to test_case_path("username") and return
        end

        if ( request.path =~ /changepassword/)
          puts '*********************** this is profile menu clicking on update password, redirecting *******************'
          redirect_to test_case_path("changepassword") and return
        end

        if ( request.path =~ /maintainmobile/)
          puts '*********************** this is profile menu clicking on update mobile, redirecting *******************'
          redirect_to test_case_path("maintainmobile") and return
        end

        if ( request.path =~ /maintainquestions/)
          puts '*********************** this is profile menu clicking on update security questions, redirecting *******************'
          redirect_to test_case_path("maintainsecurity") and return
        end

        if ( request.path =~ /deleteaccount/)
          puts '*********************** this is profile menu clicking on update security questions, redirecting *******************'
          redirect_to test_case_path("deleteuser") and return
        end

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
            ui_locales: "en-GB"
          )
        end

    end     # end if logged_in
  end # end def
  

private
  def discover
     @disco ||= OpenIDConnect::Discovery::Provider::Config.discover! 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/'
     puts '*******************discovery info***********************'
     puts @disco
     puts disco.userinfo_endpoint
     puts disco.jwks

  end

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
      #flash.now[:success] = 'Service Hint exists ' + parsed["ServiceHints"] unless parsed["ServiceHints"].nil?
      puts 'try discover.....'
      discover
      
      if (parsed["LoA"] == "L1") || (params[:LoA] == "L2") || (params[:LoA] == "L3")  
        # check user is registered with local app
        user = User.find_by(oid: jwtoid) #user = User.find_by(email: jwtemail)
       
        if user 
           puts 'tccbc:*********************** Logged in as : ' + parsed["LoA"] + '**********'
           log_in user # session_helper
           # update mobile
           puts 'tbccc: *********************** updating mobile passed from JWT **************'
           User.where(oid: jwtoid).update(mobile: jwtmobile) unless jwtmobile.nil?
           puts 'tbccc: ******* session values'
           session[:jwttokenexp]=parsed["exp"]
           session[:jwttokennbf]=parsed["nbf"]
            session[:jwttokeniss]=parsed["iss"]
            session[:jwttokeniat]=parsed["iat"]
            session[:jwttokenauth_time]=parsed["auth_time"]
            session[:jwttokenemail]=jwtemail
            session[:jwttokenmobile]=jwtmobile unless jwtmobile.nil?
            session[:jwttokenloa]=parsed["LoA"]
            session[:jwttokenoid]=jwtoid
            session[:jwttokenrpname]=parsed["rpName"]
            session[:jwttokenaud]=parsed["aud"]
            session[:jwttokenacr]=parsed["acr"] 
            session[:jwttokennonce]=parsed["nonce"]
            session[:jwtservicehints]=parsed["ServiceHints"]
            #params[:session][:remember_me] == '1' ? remember(user) : forget(user)
            session[:b2clogin]=true

            # if referral is change user name, we need to check and update local email
            if ( URI(request.referer).path.downcase =~ /updateuseremail\/api\/selfasserted\/confirmed/)
              update_user_email
            end

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
            session[:b2clogin]=true
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
  def update_user_email
    puts 'tccbc:>>>>>>>>>>>>>>>>>UPATING LOCAL USER EMAIL :' +  session[:jwttokenemail]
    puts 'tcbc>> check if email already exists'
    userchk = User.find_by(email:  session[:jwttokenemail].downcase)
    if userchk
      puts 'tcbc>> local email already exists, cant use this email: ' + session[:jwttokenemail]
    else
      userchk = User.find_by(oid:  session[:jwttokenoid])
      userchk.update_column(:email, session[:jwttokenemail])
      puts 'tcbc>> related to oid >>>' + session[:jwttokenoid]
      puts 'tcbc>> local email updated to ' + session[:jwttokenemail]
    end
  end
end # end class
