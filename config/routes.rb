Rails.application.routes.draw do
  mount RailsAdmin::Engine => '/admin', as: 'rails_admin'
  mount Sail::Engine => '/sail'
  get 'sessions/new'
  get 'users/new'
  root 'static_pages#home'
  # B2C end points pages
  get 'identity/help', to: 'static_pages#help'
  get 'identity/confidential', to: 'static_pages#confidential'
  get 'identity/forgotusername', to: 'test_case_callbacks#show'
  get 'identity/signinl3', to: 'test_case_callbacks#show'
  get 'identity/signinl2', to: 'test_case_callbacks#show'
  # if you're using the aggregate profile management page
  get 'identity/maintainmobile', to: 'test_case_callbacks#show'
  get 'identity/changeusername', to: 'test_case_callbacks#show'
  get 'identity/changepassword', to: 'test_case_callbacks#show'
  get 'identity/maintainquestions', to: 'test_case_callbacks#show'
  get 'identity/deleteaccount', to: 'test_case_callbacks#show'
  # B2C endpoint redirects
  post 'test_case_callbacks/:id', to: 'test_case_callbacks#show'
  # *********************************
  get  '/help',    to: 'static_pages#help'
  get  '/about',   to: 'static_pages#about'
  get  '/contact', to: 'static_pages#contact'
  get  '/signup',  to: 'users#new'
  get  '/b2c_user',           to: 'b2c_api#search'
  get  '/b2c_user/:id',  to: 'b2c_api#show'
  get '/servicehints',  to: 'servicehints#add'
  post '/servicehints/new',  to: 'servicehints#new'
  post '/signup',  to: 'users#create'
  get    '/login',   to: 'sessions#new'
  post   '/login',   to: 'sessions#create'
  delete '/logout',  to: 'sessions#destroy'
  get '/openid', to: 'top#show'
  
  resources :users do
    member do
      get :following, :followers
    end
  end
  resources :account_activations, only: [:edit]
  resources :microposts,          only: [:create, :destroy]
  resources :relationships,       only: [:create, :destroy]
  resources :test_cases, only: :show
  resources :test_case_callbacks, only: :show
end
#get "/foo", to: redirect('/bar')
#test use conole and app object >> app.clients_path, >>app.clients_url