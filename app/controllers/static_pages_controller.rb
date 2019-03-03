class StaticPagesController < ApplicationController
  def home  
    puts '****in home ******'
    # logger.info '*********************'
    # logger.info external_url_builder.B2C_url.to_str
    # logger.info '*********************'
    if logged_in?
      @micropost  = current_user.microposts.build
      @feed_items = current_user.feed.paginate(page: params[:page])
    end
    @b2clogin='b2c-rp-response_type-code'
  end

  def help

  end

end
