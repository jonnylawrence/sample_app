class TestCasesController < ApplicationController
  skip_before_action :verify_authenticity_token

  
  layout 'popup'
  
  def show
    sailLoA = Sail.get("LoA")

    client = TestCase.register_client!(
      params[:id],
      redirect_uri: test_case_callback_url(params[:id])
    )
 
      puts "tcc: ---------------TEST CASES PARAMS----------"
      puts params[:id]
      puts 'tcc:-------------------------------'
   
    if params[:id] == "b2c-rp-response_type-code"  # ******************** B2C PATH ****************************  
      
      puts "tcc: In generic call case - params:" + params[:id]

      session[:client_id] = Rails.application.secrets.B2C_client_id
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)
      
      # add client assertion payload, needs signing with assertion key
      # https://github.com/jwt/ruby-jwt
   
      expirey_time = 24.hours.from_now.to_i
      time_now = Time.now.to_i
      payload = { 
        LoALevelRequest: sailLoA, 
        iss: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize',
        #aud: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
        aud: 'https://b2c-ruby.herokuapp.com',
        exp: expirey_time,
        iat: time_now,
        nbf: time_now
      }

      token = JWT.encode payload, %Q{v;Eq?mY49H0Ewu;q9Y:9:)&h}, 'HS256'
      #token = JWT.encode payload, Rails.application.secrets.BC2_Assertion_secret, 'HS256'
      
      session[:token] = token
      puts 'tcc: ******* 1x Sending the following in the initial request ****************'
      puts "ID>" + session[:client_id] unless session[:client_id].nil?
      puts "STATE>" + session[:state] unless session[:state].nil?
      puts "NONCE>" + session[:nonce] unless session[:nonce].nil?
      puts "token>" + session[:token] unless session[:token].nil?
      puts "tccbc:session end*************************"
       redirect_to client.authorization_uri(
         state: session[:state],
         nonce: session[:nonce],
         scope: "openid profile",
         response_type: "id_token",
         response_mode: "form_post",
         client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
         client_assertion: token,
         ui_locales: "en-GB",
         prompt: "login",
         rp-app: "hongkong"
       )

    # ******************* maintain security  ****************************  
    elsif params[:id] == "maintainsecurity" || params[:id] == "changepassword" || params[:id] == "profile" || params[:id] == "username" || params[:id] == "logout" || params[:id] == "deleteuser"

      if params[:id] == "maintainsecurity"
          menuacr = "B2C_1A_BUID_UpdateSecurityQuestions"
      elsif params[:id] == "changepassword"
          menuacr = "B2C_1A_BUID_ResetOrChangePassword"
        elsif params[:id] == "username"
          menuacr = "B2C_1A_BUID_ChangeUsername"
        elsif params[:id] == "profile"
          menuacr = "B2C_1A_BUID_ProfileManagement"
        elsif params[:id] == "deleteuser"
          menuacr = "B2C_1A_BUID_DeleteAccount"
      end

    puts "tcc: ********* in test cases : menu options item - params:" + params[:id]
      session[:client_id] = Rails.application.secrets.B2C_client_id
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)
     
    # need to send back original JWT
    # figure out what need to be done.

    puts "tcc:>>>>>>current JWT obtained from login session helper is :" 
    puts session[:jwttokenemail]
    puts session[:jwttokenloa]
    puts "oid:" + session[:jwttokenoid]
    puts "rpname:" + session[:jwttokenrpname]
    puts "aud:" + session[:jwttokenaud]
    puts "acr:" + session[:jwttokenacr]
    puts "exp:" + Time.at(session[:jwttokenexp]).to_s 
    puts "nbf:" + Time.at(session[:jwttokennbf]).to_s 
    puts "iss:" + session[:jwttokeniss]
    puts "iat:" + Time.at(session[:jwttokeniat]).to_s
    puts "auth_time:" + Time.at(session[:jwttokeniat]).to_s 
    puts "tcc:>>>>>>>>> END <<<<<<<<<<<<<<<<"
   
    expirey_time = 24.hours.from_now.to_i
    time_now = Time.now.to_i
    payload = { 
      exp: expirey_time,
      nbf: time_now,
      iss: session[:jwttokeniss],
      aud: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
      acr: menuacr,
      nonce: session[:nonce],
      iat: time_now,
      returnPath: "https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code/",
      rpName: session[:jwttokenrpname],
      LoA: session[:jwttokenloa] 
    }

    token = JWT.encode payload, Rails.application.secrets.BC2_Assertion_secret, 'HS256'
    session[:token] = token
   
    puts 'tcc: ******* 2x Sending the following in the menu requests ****************'
    puts "ID>" + session[:client_id] unless session[:client_id].nil?
    puts "STATE>" + session[:state] unless session[:state].nil?
    puts "NONCE>" + session[:nonce] unless session[:nonce].nil?
    puts "tccbc:session end*************************"

        redirect_to client.authorization_uri(
          state: session[:state],
          nonce: session[:nonce],
          scope: "openid profile",
          response_type: "id_token",
          response_mode: "form_post",
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: token,
          ui_locales: "en-GB",
          rp-app: "hongkong"
        )
    else
      # ******************* NON-B2C PATH OPENID Dynamic Discovery ****************************  
      session[:client_id] = client.identifier
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)

          redirect_to client.authorization_uri(
            state: session[:state],
            nonce: session[:nonce],
            scope: [:profile, :email, :address, :phone]
          )
      end
  end
end  




