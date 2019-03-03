rp_identifier = if ENV['RP_IDENTIFIER'].present?
  ENV['RP_IDENTIFIER']
else
  # ['nov-rp-certified', SecureRandom.hex(8)].join('-')
  ['B2C-RUBY', SecureRandom.hex(8)].join('-')
end

if rp_identifier.blank?
  raise 'RP Identifier required.'
else
  puts "=> Start RP as '#{rp_identifier}'"
end

Rails.application.config.rp_ceritification = {
  certified: ENV['RP_CERTIFIED'] == 'true',
  # idp_base_url: 'https://rp.certification.openid.net:8080',
  # rp_identifier: rp_identifier
  idp_base_url: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize',
  rp_identifier: rp_identifier
}
Rails.application.config.rp_certification = {
  certified: ENV['RP_CERTIFIED'] == 'true',
  # idp_base_url: 'https://rp.certification.openid.net:8080',
  # rp_identifier: rp_identifier
  idp_base_url: 'https://uat-account.np.bupaglobal.com/neubgdat01atluat01b2c01.onmicrosoft.com/b2c_1a_bupa-uni-uat-signinsignup/oauth2/v2.0/authorize',
  rp_identifier: rp_identifier
}
puts "********idp base url**********<><><><><><><><><><><><><><><><><><><><><><><><><><>><"
puts Rails.application.config.rp_ceritification
puts Rails.application.config.rp_certification