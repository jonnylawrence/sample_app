Sail.configure do |config|
    config.dashboard_auth_lambda = -> { redirect_to("/") unless current_user.admin? }
  end