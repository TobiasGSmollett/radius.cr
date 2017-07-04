
module Radius
  class TunnelTypeAttribute < RadiusAttribute
    private TUNNEL_TYPE_LENGTH = 6.to_u8
    private TUNNEL_TYPE_VALUE_INDEX = 3
    private TUNNEL_TYPE_VALUE_LENGTH = 3

    getter tag
    getter tunnel_type

    def initialize(@tag, @tunnel_type)
      super AttributeType::TUNNEL_TYPE

      @data = Utils.to_3bytes(@tunnel_type.to_i32)

      @length = TUNNEL_TYPE_LENGTH
      @raw_data = Bytes.new(@length)

      @raw_data[0] = @type.to_u8
      @raw_data[1] = @length
      @raw_data[2] =
        if (tag & 0xff) == 0
          0x00
        else
          @tag
        end

      Utils.to_3bytes(@tunnel_type.to_i32)
        .copy_to @raw_data[TUNNEL_TYPE_VALUE_INDEX], TUNNEL_TYPE_LENGTH
    end
  end
end
