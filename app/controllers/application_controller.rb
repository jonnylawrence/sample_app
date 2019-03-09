class ApplicationController < ActionController::Base
#  protect_from_forgery with: :exception
  include SessionsHelper


  rescue_from(
    AttrRequired::AttrMissing,
    WebFinger::Exception,
    SWD::Exception,
    JSON::JWT::Exception,
    Rack::OAuth2::Client::Error,
    OpenIDConnect::Exception,
    with: :render_protocol_error
  )

  def render_protocol_error(e)
    @error = e
    logger.info <<~LOG
    # ERROR => #{e.message} (#{e.class})
    LOG
    render '/protocol_error'
  end

  private

    # Confirms a logged-in user.
    def logged_in_user
      puts 'logged_in_user check'
      unless logged_in?
        store_location
        flash[:danger] = "Please log in."
        redirect_to(root_url)
      end
  end
end


module UrlBuilding

  def self.included(base)
    base.helper_method :external_url_builder
  end

end
private
  
def external_url_builder
      ExternalUrlBuilder.new
end
