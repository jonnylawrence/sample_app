class ExternalUrlBuilder  < ActionController::Base

  B2C_APP_URL = ::Addressable::Template.new("https://neubgdat01buiduat01relyingparty01.azurewebsites.net/")
  SAIL_URL = ::Addressable::Template.new("https://b2c-ruby.herokuapp.com/sail/")
  SWAG_URL = ::Addressable::Template.new("https://neubgdat01buiduat01userprofile01.azurewebsites.net/")
  CSA_URL = ::Addressable::Template.new("https://neubgdat01buiduat01customerservice01.azurewebsites.net/")

  def B2C_url
    B2C_APP_URL.pattern
  end

  def SAIL_url
    SAIL_URL.pattern
  end

  def SWAG_url
    SWAG_URL.pattern
  end

  def CSA_url
    CSA_URL.pattern
  end

end

# Addressable::Template.new('http://www.windowsphone.com{/language}/store/app/-{/app_id}')
# <%= link_to "App", external_url_builder.windows_phone_8_store_url(@app, current_language) %>
# <%= link_to "login B2C", external_url_builder.B2C_APP_URL %>
# http://www.windowsphone.com{/language}/store/search{?q*}
# https://bytes.babbel.com/en/articles/2014-07-28-external-url-building.html
# Addressable::Template.new("http://www.windowsphone.com{/language}/store/search{?q*}")
#                     .expand( q: { search: "achme", created_after: "2014-01-01", limit: 10 } )
# RP ----- https://neubupagiduatrelyingparty01.azurewebsites.net/
# https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/
# b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/
# authorize?client_id=222ef181-933b-412d-9a62-c796281d8eaa&
# redirect_uri=https%3A%2F%2Fneubupagiduatrelyingparty01.azurewebsites.net%
# 2Fsignin-oidc&response_type=id_token&scope=openid%20profile&
# response_mode=form_post&
# nonce=636858379537192643.NGYyZTE1N2UtNTdmMy00NmYzLWJlNWUtZTI3ZGVlZjlkZWRhOWYwZmNiZTUtYzc5MC00YWQ4LWEyODEtOWEyZjEzY2QwNjI2
# &client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
# &client_assertion=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJMb0FMZXZlbFJlcXVlc3QiOiJMMSIsIm5iZiI6MTU1MDI0MTE1MywiZXhwIjoxNTUwMjQxNzUzLCJpYXQiOjE1NTAyNDExNTMsImlzcyI6Imh0dHBzOi8vdWF0LWFjY291bnQubnAuYnVwYWdsb2JhbC5jb20vbmV1YmdkYXQwMWF0bHVhdDAxYjJjMDEub25taWNyb3NvZnQuY29tL2IyY18xYV9idXBhLXVuaS11YXQtc2lnbmluc2lnbnVwL29hdXRoMi92Mi4wL2F1dGhvcml6ZSIsImF1ZCI6Imh0dHBzOi8vbmV1YnVwYWdpZHVhdHJlbHlpbmdwYXJ0eTAxLmF6dXJld2Vic2l0ZXMubmV0L3NpZ25pbi1vaWRjIn0.SVUIOBZDy0-2wyeYHWvj1EkIfWQ3Kar9phZF6Dje2Tg&ui_locales=en-GB&state=CfDJ8AAXplzbDrhLvpWP2MhVdoxJmaz47z2P9qh8XcuMnR5hof4kp6PEtbisXlWx_fExC7rDZzfFHyPO0nTkK7ljCCiK6wk3X8GRXgzBU9r7EfOjSpYOlhMgs2C_dgEeMz_BomRtqIfpNHJuHkLNIYEJodNDlknywqgNS134-rszTwP2WWshCoLNuiMwgwzDZi9hYPsBQUCNoqSxdIqrJBme2FY1tlZy3mfXfS4i8mOU2_uHcW20b6rLPDTQhGyWh4SbEb88_Kt6cjr8YXfW71xAv7D0c0PHfxCrTMiVhOnsjifL3PhaCDf0EUZkdFOQb1jqslnrtZP-SFYkyPglT0Sn5MvC6diU6V0SDRyd9plw5vcv
# &x-client-SKU=ID_NETSTANDARD1_4&x-client-ver=5.2.0.0

# Payload of the JWT token:
#  
# {
#   "LoALevelRequest": "L1",
#   "nbf": 1550241153,
#   "exp": 1550241753,
#   "iat": 1550241153,
#   "iss": "https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize",
#   "aud": "https://neubupagiduatrelyingparty01.azurewebsites.net/signin-oidc"
# }