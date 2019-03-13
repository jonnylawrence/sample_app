Sail.configure do |config|
    config.dashboard_auth_lambda = -> { redirect_to("/") unless session[:current_user].admin? }
  end