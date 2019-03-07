class TestCasesController < ApplicationController
  
  layout 'popup'
  
  def show
    # logger.debug '<<<<ID>>>>>&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'
    # logger.debug params[:id]
    # rp-response_type-code

    # https://github.com/nov/openid_connect/wiki/Client-Init
    # client = OpenIDConnect::Client.new(
    #   identifier: YOUR_CLIENT_ID,
    #   secret: YOUR_CLIENT_SECRET,
    #   redirect_uri: YOUR_REDIRECT_URI,
    #   host: 'server.example.com'
    # )

    client = TestCase.register_client!(
      params[:id],
      redirect_uri: test_case_callback_url(params[:id])
    )
 
      puts "---------------TEST CASES PARAMS----------"
      puts params[:id]
      puts '-------------------------------'
    # ******************* B2C PATH ****************************  
    if params[:id] == "b2c-rp-response_type-code" 
      
      puts "In generic call case - params:" + params[:id]

      session[:client_id] = Rails.application.secrets.B2C_client_id
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)
      
      # add client assertion payload, needs signing with assertion key
      # https://github.com/jwt/ruby-jwt
   
      expirey_time = 24.hours.from_now.to_i
      time_now = Time.now.to_i
      payload = { LoALevelRequest: 'L1', 
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
    # ******************* maintain security  **************************** 
    # ******************* maintain security  ****************************  
    elsif params[:id] == "maintainsecurity" 

    puts "********* in maintainsecurity questions item - params:" + params[:id]
      session[:client_id] = Rails.application.secrets.B2C_client_id
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)
     
    # need to send back original JWT
    # figure out what need to be done.

    puts ">>>>>>current JWT obtained from login session helper is :" 
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
    puts ">>>>>>>>> END <<<<<<<<<<<<<<<<"
   
    expirey_time = 24.hours.from_now.to_i
    time_now = Time.now.to_i
    payload = { 
      exp: expirey_time,
      nbf: time_now,
      iss: session[:jwttokeniss],
      aud: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
      acr: "B2C_1A_BUID_UpdateSecurityQuestions",
      nonce: session[:jwttokennonce],
      iat: time_now,
      returnPath: "https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code/",
      rpName: session[:jwttokenrpname],
      LoA: session[:jwttokenloa] 
    }

    token = JWT.encode payload, Rails.application.secrets.BC2_Assertion_secret, 'HS256'
    session[:token] = token
      # https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainsecurityquestions/oauth2/v2.0/authorize?
      #client_id=222ef181-933b-412d-9a62-c796281d8eaa&
      #redirect_uri=https%3A%2F%2Fneubgdat01buiduat01relyingparty01.azurewebsites.net%2F
      #signin-oidc&response_type=id_token&scope=openid%20profile&response_mode=form_post&
      #nonce=636873130940422076.NmZkN2I0YjMtZWNkMi00NjNiLTkxNjktM2NkOWVkMGExNWZkMzVjZDc0NmYtNzgyMC00MDYxLTg5ZGQtZTg5OTEzM2Y1MjIz&
      #client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
      #client_assertion=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE1NTE3MTYyOTQsImV4cCI6MTU1MTcxNjg5NCwiaWF0IjoxNTUxNzE2Mjk0LCJpc3MiOiJodHRwczovL3VhdC1hY2NvdW50Lm5wLmJ1cGFnbG9iYWwuY29tL25ldWJnZGF0MDFhdGx1YXQwMWIyYzAxLm9ubWljcm9zb2Z0LmNvbS9iMmNfMWFfYnVwYS11bmktdWF0LW1haW50YWluc2VjdXJpdHlxdWVzdGlvbnMvb2F1dGgyL3YyLjAvYXV0aG9yaXplIiwiYXVkIjoiaHR0cHM6Ly9uZXViZ2RhdDAxYnVpZHVhdDAxcmVseWluZ3BhcnR5MDEuYXp1cmV3ZWJzaXRlcy5uZXQvc2lnbmluLW9pZGMifQ.NFIxTO1EoTrfWQ6k17Bjzb7TdrzOj35BO_hOqpoQwyI&ui_locales=en-GB&state=CfDJ8IIR0Q9Fx-xIlkx-K2D-8GtWTYs68i2IGt_jlFrxpW52uvrvVRTMrk4kNkl6AjbtHU00LuUCj4jpmAkfD14EfzVil7loWGUabiMPlxFEIOaOP2p90UjMfWQ6kVxsgGcHSFdWeXrX6D0AYk7bTbI5mZiKRgBjzt32YC3c3Y-LqKY6v4iZDZ08yszHxalAwZQiGtP1jKbNIG4M_rAwyzYRT7qObaKwi0aye2fqhAHNf7AkIJICt_1MvwjgycCTxHq1Li_F3IOOnPlj_8xgm_DKv_8CQCHXUVVD9323kyU-kWd1S6p-gkI50eiAKGffPIlvnQXNt04qq-GnUQaS0hwXUWs
      #&x-client-SKU=ID_NETSTANDARD1_4&x-client-ver=5.2.0.0
   
      puts '******** 2 redirecting to maintain security questions ***********'
        redirect_to client.authorization_uri(
          state: session[:state],
          nonce: session[:nonce],
          scope: "openid profile",
          response_type: "id_token",
          response_mode: "form_post",
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: token,
          ui_locales: "en-GB",
          prompt: "none"
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




