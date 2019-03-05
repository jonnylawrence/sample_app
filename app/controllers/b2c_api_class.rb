
class B2cApiClass < ApplicationController
    require 'net/http'
    require 'uri'
    require 'json'
    def initialize
        
        # logger.debug '--------------------------------------'
        # special characters in the secret, held in the env string,  need to be removed
        #if Rails.env.development? 
           # stripped_client_secret=Rails.application.secrets.B2C_api_client_secret.delete_prefix("\"").
         #   delete_prefix("\\").delete_prefix("\"").delete_suffix("\"").delete_suffix("\\").tr('\\','')
            stripped_client_secret=Rails.application.secrets.B2C_api_client_secret.gsub(/\\"/,"").gsub(/\\/,"")
        #else
        #    stripped_client_secret=Rails.application.secrets.B2C_api_client_secret
        #end
        #logger.debug ">>>>>>>>>>>>>stripped 1>>>>>"+stripped_client_secret
        #logger.debug ">>>>>>>>>>>>>stripped 2>>>>>"+stripped2_client_secret
        # logger.debug "client_id-"+Rails.application.secrets.B2C_api_client_id
        # logger.debug "api_resource-"+Rails.application.secrets.B2C_api_resource
        # logger.debug '-----------stripped client secret---------------------------'
        # logger.debug stripped_client_secret
        # logger.debug Rails.application.secrets.B2C_api_client_id
        # logger.debug Rails.application.secrets.B2C_api_resource
        @response = RestClient::Request.new({
            method: :post,
            url: 'https://login.microsoftonline.com/bgmu.onmicrosoft.com/oauth2/token',
            payload: { 
            Host: 'login.microsoftonline.com', 
            grant_type: 'client_credentials',
            client_id: Rails.application.secrets.B2C_api_client_id,
            client_secret: stripped_client_secret,
            resource: Rails.application.secrets.B2C_api_resource,
            Cache_Control: 'no-cache'
            },
            headers: { Host: 'login.microsoftonline.com', 
                Content_Type: 'application/x-www-form-urlencoded', 
                Cache_Control: 'no-cache', 
                Accept: '*/*' }
                }).execute
        logger.debug @response
    end  

    def apibody
        parsed=JSON.parse(@response.body)
        p parsed["access_token"]
    end
  
    def api_search_by_email(searchemail,bearertoken)
        # *********************************************************
        #  Use this site to build the correct REST statement from CURL
        # https://jhawthorn.github.io/curl-to-ruby/
        # *********************************************************
        #curl -X POST "https://neubgdat01buiduat01userprofile01.azurewebsites.net/api/User/SearchByEmail" -H "accept: text/plain" -H "Content-Type: application/json-patch+json" -d "{ \"email\": \"string\", \"correlationId\": \"string\"}"
        @b2cemail=searchemail
        @bc2bearertoken=bearertoken

        uri = URI.parse("https://neubgdat01buiduat01userprofile01.azurewebsites.net/api/User/SearchByEmail")
        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json-patch+json"
        request["Accept"] = "text/plain"
        request["Authorization"] = @bc2bearertoken
        request.body = JSON.dump({   
        "email" => @b2cemail,
        "correlationId" => "123"
        })

        req_options = {
        use_ssl: uri.scheme == "https",
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
        end

       # logger.debug '--------------------------------------'
       # logger.debug request["Authorization"] 
       # logger.debug "email-"+@b2cemail+"END"
       # logger.debug response.code
       # logger.debug response.body
       # logger.debug '--------------------------------------'
        response.body
       
    end

    def reset
        @b2cbearertoken=nil
    end

    def api_add_service_hint(objectId,policyId,org,userType,systemId,productId)
    #     # *********************************************************
    #     #  Use this site to build the correct REST statement from CURL
    #     # https://jhawthorn.github.io/curl-to-ruby/
    #     # *********************************************************

         @b2cobjectId=objectId
         @b2cpolicyId=policyId
         @b2corg=org
         @b2cuserType=userType
         @b2csystemId=systemId
         @b2cproductId=productId

          #logger.debug ">>>>>>>>>>>>>vars>>>>>OBJ"+@b2cobjectId+" POL"+@b2cpolicyId+" ORG"+@b2corg+" UT"+@b2cuserType+" SYS"+@b2csystemId+" PROD"+@b2cproductId
          #logger.debug ">>>>>>>>>secret "+Rails.application.secrets.B2C_api_basic
          uri = URI.parse("https://neubgdat01buiduat01userprofile01.azurewebsites.net/api/ServiceHintsB2c/AddServiceHint")
          request = Net::HTTP::Post.new(uri)
          request.content_type = "application/json-patch+json"
          request["Accept"] = "text/plain"
          request["Authorization"] = Rails.application.secrets.B2C_api_basic
          request.body = JSON.dump({
          "objectId" => @b2cobjectId,
          "value" => {},
          "correlationId" => "123",
          "policyId" => @b2cpolicyId,
          "org" => @b2corg,
          "userType" => @b2cuserType,
          "systemId" => @b2csystemId,
          "productId" => @b2cproductId
          })

          req_options = {
              use_ssl: uri.scheme == "https",
          }

          response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
              http.request(request)
          end
          response.body
          response.code
    end

end