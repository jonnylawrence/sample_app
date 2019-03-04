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
    # ******************* RP in menu option  ****************************  
    elsif params[:id] == "maintainsecurity" 

    puts "In call case for menu item - params:" + params[:id]
    session[:client_id] = Rails.application.secrets.B2C_client_id
      session[:state] = SecureRandom.hex(16)
      session[:nonce] = SecureRandom.hex(16)
     
    # need to send back original JWT
    # figure out what need to be done.

    puts ">>>>>>current JWT obtained from login session helper is :" 
    puts session[:jwttokenemail]
    puts session[:jwttokenloa]
    puts session[:jwttokenoid]
    puts session[:jwttokenrpname]
    puts session[:jwttokenaud]
    puts session[:jwttokenacr]
    puts session[:jwttokenexp]
    puts session[:jwttokennbf]
    puts session[:jwttokeniss]
    puts session[:jwttokeniat]
    puts session[:jwttokenauth_time]
    puts session[:jwttokennonce]
    puts ">>>>>>>>> END <<<<<<<<<<<<<<<<"
   
    expirey_time = 24.hours.from_now.to_i
    time_now = Time.now.to_i
    payload = { 
      exp: expirey_time,
      nbf: time_now,
      ver: "1.0",
      iss: session[:jwttokeniss],
      sub: "Not supported currently. Use oid claim.",
      aud: session[:jwttokenaud],
      acr: session[:jwttokenacr],
      nonce: session[:jwttokennonce],
      iat: time_now,
      auth_time: session[:jwttokenauth_time],
      returnPath: "unspecified",
      rpName: session[:jwttokenrpname],
      LoA: session[:jwttokenloa] 
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




