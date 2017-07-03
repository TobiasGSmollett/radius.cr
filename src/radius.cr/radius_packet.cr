module Radius
  class RadiusPacket
    private RADIUS_CODE_INDEX = 0_u8
    private RADIUS_IDENTIFIER_INDEX = 1_u8
    private RADIUS_LENGTH_INDEX = 2_u8
    private RADIUS_AUTHENTICATOR_INDEX = 4_u8
    private RADIUS_AUTHENTICATOR_FIELD_LENGTH = 16_u8
    private RADIUS_MESSAGE_AUTH_HASH_LENGTH = 16_u8
    private RADIUS_MESSAGE_AUTHENTICATOR_LENGTH = 18_u8
    private ATTRIBUTES_INDEX = 20_u8
    private RADIUS_HEADER_LENGTH = ATTRIBUTES_INDEX

    def initialize(@packet_type, @identifier = SecureRandom.random_bytes)
      @attributes = Array(RadiusAttribute).new
      @authenticator = Bytes.new(RADIUS_AUTHENTICATOR_FIELD_LENGTH)

      @length = RADIUS_HEADER_LENGTH

      @raw_data = Bytes.new(RADIUS_HEADER_LENGTH)
      @raw_data[RADIUS_CODE_INDEX] = @packet_type
      @raw_data[RADIUS_IDENTIFIER_INDEX] = @identifier


      length_bytes = Bytes.new(sizeof(UInt16))
      length_bytes[1] = 2_u8
      length_bytes.reverse!
      length_bytes.copy_to @raw_data[RADIUS_LENGTH_INDEX], sizeof(UInt16)
    end

    def initialize(receive_data)
      @attributes = Array(RadiusAttribute).new
      @authenticator = Bytes.new(RADIUS_AUTHENTICATOR_FIELD_LENGTH)

      @valid = true
      @raw_data = receive_data

      if(@raw_data.length < 20 || 2096 < @raw_data.length)
        @valid = false
      else
        @packet_type = @raw_data[RADIUS_CODE_INDEX]
        @identifier = @raw_data[RADIUS_IDENTIFIER_INDEX]
        @length = ((@raw_data[2] << 8) + @raw_data[3]).to_u8

        if @length > @raw_data.length
          @valid = false
        else
          @raw_data.copy_to @authenticator, 0, RADIUS_AUTHENTICATOR_FIELD_LENGTH

          attributes_array = Bytes.new(@length - ATTRIBUTES_INDEX)
          attributes_array.copy_from receive_data[ATTRIBUTES_INDEX, attributes_array.length]
          parse_attributes attributes_array
        end
      end
    end

    def authenticator=(shared_secret, request_authenticator = nil)
      case packet_type
      when RadiusCode.ACCESS_REQUEST
        @authenticator = Utils.access_request_authenticator shared_secret
      when RadiusCode.ACCESS_ACCEPT
        @authenticator = Utils.response_authenticator @raw_data, request_authenticator, shared_secret
      when RadiusCode.ACCESS_REJECT
      when RadiusCode.ACCOUNTING_REQUEST
        @authenticator = Utils.accounting_request_authenticator @raw_data, shared_secret
      when RadiusCode.ACCOUNTING_RESPONSE
        @authenticator = Utils.response_authenticator @raw_data, request_authenticator, shared_secret
      when RadiusCode.ACCOUNTING_STATUS
      when RadiusCode.PASSWORD_REQUEST,
           RadiusCode.PASSWORD_ACCEPT,
           RadiusCode.PASSWORD_REJECT,
           RadiusCode.ACCOUNTING_MESSAGE,
           RadiusCode.ACCESS_CHALLENGE
      when RadiusCode.SERVER_STATUS
        @authenticator = Utils.access_request_authenticator shared_secret
      when RadiusCode.COA_REQUEST
        @authenticator = Utils.accounting_request_authenticator @raw_data, shared_secret
      when RadiusCode.DISCONNECT_REQUEST
        @authenticator = Utils.accounting_request_authenticator @raw_data, shared_secret
      else
        raise Exception.new "argument out of range"
      end
    end

    def identifier=(id)
      @identifier = id
      @raw_data[RADIUS_IDENTIFIER_INDEX] = @identifier
    end

    def attribute=(attribute)
      @attributes << attribute

      new_raw_data = Bytes.new(@raw_data.length + attribute.length)
      @raw_data.copy_to new_raw_data
      attribute.@raw_data.copy_to new_raw_data[@raw_data.length, attribute.@length]

      @raw_data = new_raw_data
      @length = raw_data.length

      tmp = Bytes.new(sizeof(UInt16))
      tmp[1] = @length.to_u8
      tmp.reverse!
      tmp.copy_to @raw_data[RADIUS_LENGTH_INDEX, sizeof(UInt16)]
    end

    def message_authenticator=(shared_secret)
      new_raw_data = Bytes.new(@raw_data.length + RADIUS_MESSAGE_AUTHENTICATOR_LENGTH)
      new_raw_data = @raw_data

      tmp = Bytes.new(sizeof(UInt16))
      tmp[1] = @length.to_u8
      tmp.reverse!
      tmp.copy_to new_raw_data[RADIUS_LENGTH_INDEX, sizeof(UInt16)]

      new_raw_data[@raw_data.length] = AttributeType.MESSAGE_AUTHENTICATOR
      new_raw_data[@raw_data.length + 1] = RADIUS_MESSAGE_AUTHENTICATOR_LENGTH

      hash = OpenSSL::HMAC.digest(:md5,shared_secret,new_raw_data)
      hash.copy_to new_raw_data[new_raw_data.length - RADIUS_MESSAGE_AUTH_HASH_LENGTH, hash.length]
      @rawdata = new_raw_data
      @length += RADIUS_MESSAGE_AUTHENTICATOR_LENGTH
    end

    private def parse_attributes(attribute_byte_array)
      current_attribute_offset = 0

      while current_attribute_offset < attribute_byte_array.length
        type = attribute_byte_array[current_attribute_offset]
        length = attribute_byte_array[current_attribute_offset + 1]

        if length < 2 || current_attribute_offset + length > @length
          @valid = false
          return
        end

        data = Bytes.new(length - 2)
        data.copy_from attribute_byte_array[current_attribute_offset + 2, length - 2]

        @attributes <<
          if type == AttributeType.VENDOR_SPECIFIC
            VendorSpecificAttribute.new(attribute_byte_array, current_attribute_offset)
          else
            RadiusAttribute.new(type, data)
          end

        current_attribute_offset += length
      end
    end
  end
end
