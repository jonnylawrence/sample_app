
# frozen_string_literal: true


  # Decoding logic for JWT
  class Decode < ApplicationController
    require 'json'
    require 'jwt'
    attr_reader :header, :payload, :signature

    def self.base64url_decode(str)
      str += '=' * (4 - str.length.modulo(4))
      Base64.decode64(str.tr('-_', '+/'))
    end

    def initialize(jwt, verify)
      @jwt = jwt
      @verify = verify
      logger.debug ">>>>>>>>>>>>>stripped 1>>>>>"
    end

    def decode_segments
      header_segment, payload_segment, crypto_segment = raw_segments(@jwt, @verify)
      @header, @payload = decode_header_and_payload(header_segment, payload_segment)
      @signature = Decode.base64url_decode(crypto_segment.to_s) if @verify
      signing_input = [header_segment, payload_segment].join('.')
      [@header, @payload, @signature, signing_input]
    end

    private

    def raw_segments(jwt, verify)
      segments = jwt.split('.')
      required_num_segments = verify ? [3] : [2, 3]
      raise(JWT::DecodeError, 'Not enough or too many segments') unless required_num_segments.include? segments.length
      segments
    end

    def decode_header_and_payload(header_segment, payload_segment)
      header = JSON.parse(Decode.base64url_decode(header_segment))
      payload = JSON.parse(Decode.base64url_decode(payload_segment))
      [header, payload]
    rescue JSON::ParserError
      raise JWT::DecodeError, 'Invalid segment encoding'
    end
  
end