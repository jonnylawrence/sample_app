Sail.configure do |config|
    puts session[:user_id]
    config.dashboard_auth_lambda = -> { redirect_to("/") unless session[:user_id] =~ /pop/ }
  end