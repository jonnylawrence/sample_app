class B2cApiController < ApplicationController
    before_action :logged_in_user
    before_action :admin_user,     only: :show
    
    def search
    end

    def show
        @email=params[:f]
        @token=B2cApiClass.new
        @token.reset
        @b2c_email_results=@token.api_search_by_email(@email,"Bearer "+@token.apibody)

        logger.debug '-------->'+@b2c_email_results+'<----------'
        if @b2c_email_results != ""
            responseparsed=JSON.parse(@b2c_email_results)
            @rp_objectid=responseparsed["objectId"]
        else
            flash.now[:danger] = 'No user found with this email'
            render 'search'
        end
    
    end

    private

     # Confirms an admin user.
     def admin_user
        redirect_to(root_url) unless current_user.admin?
     end

     

end
