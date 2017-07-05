
module Radius

  class RadiusAttribute

    ATTRIBUTE_HEADER_SIZE = 2.to_u8

    @type : AttributeType
    @data : Bytes

    getter type, length, raw_data

    def value
      case type
      when AttributeType::NAS_IP_ADDRESS,
           AttributeType::NAS_IPV6_ADDRESS,
           AttributeType::FRAMED_IP_ADDRESS,
           AttributeType::FRAMED_IP_NETMASK,
           AttributeType::LOGIN_IP_HOST,
           AttributeType::LOGIN_IPV6_HOST
        Socket::IPAddress.new(@data, @data.size).to_s
      when AttributeType::FRAMED_PROTOCOL,
           AttributeType::FRAMED_IPV6_PREFIX
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::FRAMED_ROUTING
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::SERVICE_TYPE
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::FRAMED_COMPRESSION
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::LOGIN_SERVICE
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::FILTER_ID,
           AttributeType::CALLBACK_NUMBER,
           AttributeType::REPLY_MESSAGE
        @data.to_s
      when AttributeType::FRAMED_MTU,
           AttributeType::LOGIN_TCP_PORT
        result = @data.dup
        result.reverse!
        result.to_i32
      when AttributeType::TUNNEL_TYPE
        Utils.three_bytes_to_uint(@data, 0).to_s
      when AttributeType::TUNNEL_MEDIUM_TYPE
        Utils.three_bytes_to_uint(@data, 0).to_s
      else
        @data.to_s
      end
    end

    def initialize(@type)
      @data = Bytes.new 0
      @raw_data = Bytes.new 0
      @length = 0
    end

    def initialize(@type, @data : Bytes)
      @length = @data.size + ATTRIBUTE_HEADER_SIZE
      @raw_data = Bytes.new(@length)
      @raw_data[0] = @type.value.to_u8
      @raw_data[1] = @length.to_u8
      @data.copy_from @raw_data[ATTRIBUTE_HEADER_SIZE, @data.size]
    end

    def self.create(type, data : Int)
      RadiusAttribute.new(type, Utils.get_network_bytes(data))
    end
  end

end
