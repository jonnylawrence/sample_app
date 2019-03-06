class StaticPagesController < ApplicationController
  def home  
    puts '****in home static pages controller******'
    # logger.info '*********************'
    # logger.info external_url_builder.B2C_url.to_str
    # logger.info '*********************'

    puts '<<<b2clogin session and email'
    puts session[:b2clogin] 
    puts session[:jwttokenemail]
    puts '<<<<<<<<<<<<<>>>>>>>>>>'
    # to check if these are register
    if session[:b2clogin] # come from B2C
      puts "<<<<<<<<<<< FROM B2C >>>>>>>>>>>>"
      if !User.find_by(email: session[:jwttokenemail].downcase)
        # not found in the database
        puts "<<<<<<<<<< B2C NOT FOUND IN DATABASE REDIRECT TO REGISTRATION>>>>>>>"
        Redirect_to sign_up_path
      end
    end

    if logged_in? 
      @micropost  = current_user.microposts.build
      @feed_items = current_user.feed.paginate(page: params[:page])
    end

    @b2clogin='b2c-rp-response_type-code'
  end

  def help

  end

end
