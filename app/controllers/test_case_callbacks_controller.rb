class TestCaseCallbacksController < ApplicationController
  require 'jwt'
  require 'json'
  require 'net/http'
  require 'uri'
  require 'json/jwt'
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
          puts 'tccbc: ******* Sending the following in the call back request ****************'
          puts "ID>" + session[:client_id] unless session[:client_id].nil?
          puts "STATE using old state>" + params[:state] unless params[:state].nil?
          puts "NONCE>" + session[:nonce] unless session[:nonce].nil?
          puts "token>" + session[:token] unless session[:token].nil?
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
  def do_IDPmetadatadiscovery
    if !session[:b2cissuer]
      puts 'tccb: getting meta data from B2C OID discovery endpoint...'
      uri = URI.parse("https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=b2c_1a_bupa-uni-uat-signinsignup")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Get.new(uri.request_uri)
      response = http.request(request)
      parsed = JSON.parse(response.body)
      session[:b2cissuer]=parsed["issuer"]
    else
      puts 'tccc: issuer : ' + session[:b2cissuer]
    end
  end

  def check_JWTsignature
    # HOW TO VALIDATE A TOKEN
    # https://connect2id.com/blog/how-to-validate-an-openid-connect-id-token
    # discovery page
    # https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=b2c_1a_bupa-uni-uat-signinsignup
    # https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1a_bupa-uni-uat-signinsignup
    # https://github.com/nov/json-jwt/wiki/JWS
     if !session[:b2ckid]
      puts 'tccb: getting kid from B2C OID discovery endpoint for keys....'
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
     end
      puts 'tccc: b2ckid: ' + session[:b2ckid] unless session[:b2ckid].nil?
      puts 'tccc: b2cn:' + session[:b2cn] unless session[:b2cn].nil?
      puts 'tccc: b2ce:' + session[:b2ce] unless session[:b2ce].nil?
      puts 'tccc: b2calg:' + session[:b2calg] unless session[:b2calg].nil?

    public_key = JSON::JWK.new(
      kty: 'RSA',
      e: session[:b2ce],
      n: session[:b2cn]
    )
    # check alg
    case session[:b2calg]
    when /RS/
      puts 'tccb: Good news - match for RSA'
    else 
      puts 'tccb: Bad news - no match for JWT alogorithm !!!!!'
    end

    # check kid
    if session[:jwttokenkid] == session[:b2ckid]
      puts 'tccb: Good news, kid token  matches with discovery keys kid'
    else
      puts 'tccb: Bad news, kid does not match between discovery keys and JWT token !!!!!!!'
    end
    # check signatire
    jwt = JSON::JWT.decode params[:id_token], public_key
    if jwt.verify! public_key
      puts 'tccb: ***** JWT SIGNATURE IS GOOD! *******'
    else
      puts 'tccb: !!!!!!!!!!!! JWT SIGNATURE IS BAD !!!!!!!!!!!!!'
      # need to redirect to login page, but won't bother!
    end
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
    # puts 'tccbc; *************** printing cookies ***********'
    # cookies.each do |cookie|
    #   puts cookie
    # end
    puts "tccbc: ******************    checking token ******************************"
    puts params[:LoA]
    puts "tccbc: Checking body for the token........"
    puts "Checking for state in the body..."
    puts params[:state]
    puts "-----------------------------------------------------------------------"

    # check body for a L2 Token, although token needs to be checked below
    if (params[:LoA] == "L1") || (params[:LoA] == "L2")  || (params[:LoA] == "L3")  
      puts '*********** OK L1, L2, L3 found in the body therefore now checking ID token validity....'
     # puts 'all of the token >>>>>>>>>.'
     # puts params[:id_token]
      @b2cjwt=Decode.new(params[:id_token],Rails.application.secrets.BC2_Assertion_secret)
      @b2cjwt.decode_segments
      puts '************ loading header of token *****************'
      @sts_header =@b2cjwt.header.to_json
      puts @sts_header
      parsed_header = JSON.parse(@sts_header)
      session[:jwttokenkid]=parsed_header["kid"]
      session[:jwttokenalg]=parsed_header["alg"]
      puts '************ loading payload *****************'
      @sts = @b2cjwt.payload.to_json
      parsed = JSON.parse(@sts)
      jwtemail=parsed["email"].downcase
      jwtoid=parsed["oid"]
      jwtmobile=parsed["mobile"]
  
      puts 'tccbc:>>>>>>>>>TOKEN OUTPUT START<<<<<<<<<<<<<'
      puts "LOA> " + parsed["LoA"]
      puts "email> " + jwtemail
      puts "iss - does the token originate from IdP? > " + parsed["iss"]
      # Need to validate issuer using discovery endpoint and return JWT issuer
      #
      do_IDPmetadatadiscovery
 
      puts "OID> " + jwtoid
      puts "mobile" + jwtmobile unless jwtmobile.nil?
      puts "exp - is the token within its validity window? > " + Time.at(parsed["exp"]).to_s
      puts "nbf - is the token within its validity window?> " + Time.at(parsed["nbf"]).to_s
      puts "aud -  is the token intended for me and it matches my client id?> " + parsed["aud"]
      puts "acr> " + parsed["acr"]
      puts "nonce - if set, does it tie to a request of my own?> " + parsed["nonce"]
      puts "iat> " + Time.at(parsed["iat"]).to_s
      puts "auth_time> " + Time.at(parsed["auth_time"]).to_s
      puts "rpName> " + parsed["rpName"]
      puts "ServiceHints> " + parsed["ServiceHints"]
      if parsed["iss"] == session[:b2cissuer]
        puts '**** Good news Issuer [in assertion token] matches'
      else
        puts '!!!! Bad news Issuer Does NOT match!!!!!!!!!'
      end
     
      if parsed["aud"] == Rails.application.secrets.B2C_client_id
        puts '**** Good news audience [in assertion token] matches my client_id'
      else
        puts '!!!! Bad news audience does NOT match my client_id !!!!!!!!!'
      end
      puts "------ State and nonce are generated by client. Similarly, they are validated by client. state prevents CSRF attacks."
      if session[:nonce] == parsed["nonce"]
        puts '**** Good new, Nonce [in assertion token] ties back to the request'
      else 
        puts '!!!! Bad news, Nonce does not tie back to the request'
      end
      #puts "params state is " + params[:state].to_s
      #puts "session state is " + session[:state].to_s
       if params[:state].to_s == session[:state].to_s
        puts '**** Good news state [in the packet body] matches the returned value'
      else
        puts '!!!! Bad news state does NOT match returned value CSRF Attack !!!!!!!!!'
      end
      puts 'tccbc:>>>>>>>>>TOKEN OUTPUT END<<<<<<<<<<<<<'      
      puts '<><><><>< validating token signature <><><><><><><'
      #
      # Need to check signature for token
      #
      check_JWTsignature
      #
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

            # reroute based on return from signl3 elevate and who asked for it
            if session[:redirect] == "confidential" 
              session[:redirect] = ""
              redirect_to confidential_path and return
            else
              redirect_to root_path and return
            end


            
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
