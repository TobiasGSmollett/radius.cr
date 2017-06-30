
module Radius

  class RadiusAttribute

    protected ATTRIBUTE_HEADER_SIZE = 2.to_u8

    getter type, length, raw_data

    def value
      case type
      when AttributeType::NAS_IP_ADDRESS,
           AttributeType::NAS_IPV6_ADDRESS,
           AttributeType::FRAMED_IP_ADDRESS,
           AttributeType::FRAMED_IP_NETMASK,
           AttributeType::LOGIN_IP_HOST,
           AttributeType::LOGIN_IPV6_HOST

      when AttributeType::FRAMED_PROTOCOL,
           AttributeType::FRAMED_IPV6_PREFIX

      when AttributeType::FRAMED_ROUTING

      when AttributeType::SERVICE_TYPE

      when AttributeType::FRAMED_COMPRESSION

      when AttributeType::LOGIN_SERVICE

      when AttributeType::FILTER_ID,
           AttributeType::CALLBACK_NUMBER,
           AttributeType::REPLY_MESSAGE

      when AttributeType::FRAMED_MTU,
           AttributeType::LOGIN_TCP_PORT

      when AttributeType::TUNNEL_TYPE

      when AttributeType::TUNNEL_MEDIUM_TYPE

      else

      end
    end

    def initialize(@type)
    end

    def initialize(@type, @data)
      @length = @data.size + ATTRIBUTE_HEADER_SIZE
      @raw_data = Bytes.new(@length)
      @raw_data[0] = @type
      @raw_data[1] = @length
    end

    def self.create(type, data)
      RadiusAttribute.new(type, Utils.get_network_bytes(data))
    end
  end

end
