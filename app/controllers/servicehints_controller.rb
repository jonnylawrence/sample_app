class ServicehintsController < ApplicationController
    before_action :logged_in_user
    before_action :admin_user,     only: :show
    
    def add
        @objectid_passed=params['objectid']
    end

    def new
        @objectId=params[:objectid]
        @policyId=params[:policyid]
        @org=params[:org]
        @userType=params[:usertype]
        @systemId=params[:systemid]
        @productId=params[:productid]
       
        @token=B2cApiClass.new
        @token.reset
        @b2c_service_results=@token.api_add_service_hint(@objectId,@policyId,@org,@userType,@systemId,@productId,"Bearer "+@token.apibody)

        if @b2c_service_results == '200'
            flash.now[:success] = 'Service Hint added to ' + @objectId
        else
            flash.now[:danger] = 'Service Hint failed to be added for ' + @objectId + ' with return code ' + @b2c_service_results
        end
    end

    private

     # Confirms an admin user.
    def admin_user
        redirect_to(root_url) unless current_user.admin?
    end

end
