Sail.configure do |config|
    puts session[:user_id] session[:user_id].nil?
    config.dashboard_auth_lambda = -> { redirect_to root_path unless session[:user_id] =~ /pop/ }
  end