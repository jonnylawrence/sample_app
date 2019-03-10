class UsersController < ApplicationController
  before_action :logged_in_user, only: [:index, :edit, :update, :destroy]
  before_action :correct_user,   only: [:edit, :update]
  before_action :admin_user,     only: :destroy
  #skip_before_action :verify_authenticity_token
  require 'json'


  def index
    @users = User.paginate(page: params[:page])
  end

  def show
    @user = User.find(params[:id])
    @microposts = @user.microposts.paginate(page: params[:page])
  end

  def new
    puts '<<<<<< in users create>>>>'
    puts session[:email]
    puts session[:oid]
    puts '<<<<<<<<<<remove dummy email >>>>>>>>>>>>>>>'
    dummyuser = User.find_by(email: "dummy@dummy.com").destroy
    puts '<<<<<<<<<< dummy removed >>>>>>>>>>>>>>>'
    @user = User.new
  end

  def create
    
    @user = User.new(user_params)
    if @user.save # && verify_recaptcha(model: @user)
      log_in @user
     
      # add service hint here
      puts "uc: oid: " + session[:jwttokenoid]
      puts "uc: policy: " + params[:user][:member] unless params[:user][:member].nil?
      @objectId=session[:jwttokenoid]
      @policyId=params[:user][:member]
      @org="ANZ"
      @userType="Member"
      @systemId="Ruby-B2C"
      @productId="InsuranceZZZZ"
     
      @token=B2cApiClass.new
      @token.reset
      @b2c_service_results=@token.api_add_service_hint(@objectId,@policyId,@org,@userType,@systemId,@productId,"Bearer "+@token.apibody)

      if @b2c_service_results == '200'
          flash.now[:success] = 'Service Hint added to ' + @objectId
      else
          flash.now[:danger] = 'Service Hint failed to be added for ' + @objectId + ' with return code ' + @b2c_service_results
      end
      redirect_to(root_url)
    else
      render 'new'
    end
  end

  def edit
    @user = User.find(params[:id])
  end

  def update
    @user = User.find(params[:id])
    if @user.update_attributes(user_params)
      flash[:success] = "Profile updated"
      redirect_to @user
      # Handle a successful update.
    else
      render 'edit'
    end
  end

  def destroy
    User.find(params[:id]).destroy
    flash[:success] = "User deleted"
    redirect_to users_url
  end

  def following
    @title = "Following"
    @user  = User.find(params[:id])
    @users = @user.following.paginate(page: params[:page])
    render 'show_follow'
  end

  def followers
    @title = "Followers"
    @user  = User.find(params[:id])
    @users = @user.followers.paginate(page: params[:page])
    render 'show_follow'
  end

  private

    def user_params
      params[:user][:password]="0racle"
      params[:user][:password_confirmation]="0racle"
      params.require(:user).permit(:name, :email, :dob, :member, :password, 
                                   :password_confirmation, :oid, :mobile)
    end

    # Confirms the correct user.
    def correct_user
      puts '<><><><>< correct user check'
      @user = User.find(params[:id])
      redirect_to(root_url) unless current_user?(@user)
    end

    # Confirms an admin user.
    def admin_user
      puts '<><><><><admin user'
      redirect_to(root_url) unless current_user.admin?
    end
end