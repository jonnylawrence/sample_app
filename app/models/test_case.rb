class TestCase < ApplicationRecord
  has_many :clients

  before_validation :setup, on: :create
  validates :identifier, presence: true
  validates :issuer,     presence: true, uniqueness: true

  class << self
    def register_client!(identifier, options = {})
      test_case = find_or_create_by!(identifier: identifier)
      client = test_case.register_client! options
    end

    def validate!(identifier, options = {})
      test_case = find_by!(identifier: identifier)
      test_case.validate! options
    end
  end

  def register_client!(options = {})
    #logger.debug "START&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
    #logger.debug options[:redirect_uri]
    # http://localhost:3000/test_case_callbacks/rp-response_type-code
    #logger.debug "MIDDLE&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
    #logger.debug config.registration_endpoint
    # https://rp.certification.openid.net:8080/nov-rp-certified-002b27fd6ea579f3/rp-response_type-code/registration
    #logger.debug "END&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&"
    Client.delete_all
    # logger.debug "------------------identifier---------------------"
    # logger.debug "#{identifier}"
    # logger.debug Rails.application.secrets.B2C_client_id
    # # rp-response_type-code
    # logger.debug "------------------identifier---------------------"

    if identifier == "b2c-rp-response_type-code"
      client = OpenIDConnect::Client.new(
        identifier: "8514ac6a-922e-45cb-bdc0-0d6f2407edce"
        #identifier: Rails.application.secrets.B2C_client_id,
        secret: "v;Eq?mY49H0Ewu;q9Y:9:)&h",
        #secret: Rails.application.secrets.B2C_client_secret,
        redirect_uri: 'https://bupa-hk-qa.healthtap.com/member/oauth/login/redirect'
        #redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
        host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize',
        authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize'
      )
    elsif identifier == "maintainsecurity"
      client = OpenIDConnect::Client.new(
        identifier: Rails.application.secrets.B2C_client_id,
        secret: Rails.application.secrets.B2C_client_secret,
        redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
        host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainsecurityquestions/oauth2/v2.0/authorize',
        authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainsecurityquestions/oauth2/v2.0/authorize'
      )
      elsif identifier == "changepassword"
        client = OpenIDConnect::Client.new(
          identifier: Rails.application.secrets.B2C_client_id,
          secret: Rails.application.secrets.B2C_client_secret,
          redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
          host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize',
          authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-passwordreset/oauth2/v2.0/authorize'
        )
      elsif identifier == "maintainmobile"
        client = OpenIDConnect::Client.new(
          identifier: Rails.application.secrets.B2C_client_id,
          secret: Rails.application.secrets.B2C_client_secret,
          redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
          host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainmobilenumber/oauth2/v2.0/authorize',
          authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-maintainmobilenumber/oauth2/v2.0/authorize',
          )
        elsif identifier == "username"
          client = OpenIDConnect::Client.new(
            identifier: Rails.application.secrets.B2C_client_id,
            secret: Rails.application.secrets.B2C_client_secret,
            redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
            host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-updateuseremail/oauth2/v2.0/authorize',
            authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-updateuseremail/oauth2/v2.0/authorize',
            )
          elsif identifier == "profile"
            client = OpenIDConnect::Client.new(
              identifier: Rails.application.secrets.B2C_client_id,
              secret: Rails.application.secrets.B2C_client_secret,
              redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
              host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-profilemanagement/oauth2/v2.0/authorize',
              authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-profilemanagement/oauth2/v2.0/authorize',
              )
            elsif identifier == "deleteuser"
              client = OpenIDConnect::Client.new(
                identifier: Rails.application.secrets.B2C_client_id,
                secret: Rails.application.secrets.B2C_client_secret,
                redirect_uri: 'https://b2c-ruby.herokuapp.com/test_case_callbacks/b2c-rp-response_type-code',
                host: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-deleteaccount/oauth2/v2.0/authorize',
                authorization_endpoint: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-deleteaccount/oauth2/v2.0/authorize',
                )

    # all other cases - this is dynamic registration
    else
      client = OpenIDConnect::Client::Registrar.new(
        config.registration_endpoint,
        client_name:      "RP - #{identifier}",
        application_type: 'web',
        redirect_uris:    [options[:redirect_uri]],
        contacts:         ['jon@mytest.com']
      ).register!
      client = clients.create!(
      identifier: client.identifier,
      secret:     client.secret
      )
      client.agent_for config, options
    end
  end

  def validate!(options = {})
    access_token, id_token, id_token_jwt = if options[:code].present?
      validate_token_request! options
    end
    user_info = if access_token.present?
      validate_user_info! access_token, id_token, options
    end
    [access_token, id_token, id_token_jwt, user_info]
  end

  private

  def validate_token_request!(options = {})
    client = clients.find_by!(identifier: options[:client_id])
    client = client.agent_for config, options
    client.authorization_code = options[:code]
    access_token = client.access_token!
    id_token, id_token_jwt = validate_id_token! access_token.id_token, config.jwks, options
    [access_token, id_token, id_token_jwt]
  end

  def validate_id_token!(id_token_string, jwks, options = {})
    id_token_jwt = JSON::JWT.decode id_token_string, :skip_verification
    id_token = if id_token_jwt.header[:alg] == 'none'
      OpenIDConnect::ResponseObject::IdToken.decode id_token_string, :skip_verification
    else
      jwk_or_jwks = if id_token_jwt.header[:kid].present?
        jwks
      else
        expected_kty = case id_token_jwt.header[:alg]
        when /RS/
          'RSA'
        when /ES/
          'EC'
        end
        jwks_selected = jwks.select do |jwk|
          jwk[:use] == 'sig' && jwk[:kty] == expected_kty
        end
        case jwks_selected.size
        when 0
          raise JSON::JWK::Set::KidNotFound, "No keys are found for kyt=#{expected_kty} & use=sig"
        when 1
          jwks_selected.first
        else
          raise JSON::JWK::Set::KidNotFound, "Multiple keys are found for kyt=#{expected_kty} & use=sig"
        end
      end
      OpenIDConnect::ResponseObject::IdToken.decode id_token_string, jwk_or_jwks
    end
    id_token.verify!(
      issuer:   issuer,
      audience: options[:client_id],
      nonce:    options[:nonce]
    )
    [id_token, id_token_jwt]
  end

  def validate_user_info!(access_token, id_token, options = {})
    user_info = access_token.userinfo!
    if id_token.sub != user_info.sub
      raise OpenIDConnect::Exception, '"sub" mismatch between ID Token and UserInfo'
    end
    user_info
  end

  def config
     @config ||= OpenIDConnect::Discovery::Provider::Config.discover! issuer
   end

  def setup
    self.issuer = if identifier
      File.join(
        Rails.application.config.rp_ceritification[:idp_base_url],
        Rails.application.config.rp_ceritification[:rp_identifier],
        identifier
      )
    end
  end
end
