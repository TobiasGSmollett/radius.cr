
module Radius
  class TunnelMediumTypeAttribute < RadiusAttribute
    private TUNNEL_TYPE_LENGTH = 6.to_u8
    private TUNNEL_TAG_INDEX = 2.to_u8
    private TUNNEL_TYPE_VALUE_INDEX = 3
    private TUNNEL_TYPE_VALUE_LENGTH = 3

    getter tag
    getter tunnel_medium_type

    def initialize(@tag, @tunnel_medium_type)
      super Radius::AttributeType.TUNNEL_TYPE

      @data = Utils.IntTo3Byte(@tunnel_medium_type.to_i32)

      @length = TUNNEL_TYPE_LENGTH
      @raw_data = Bytes.new(@length)

      @raw_data[0] = @type.to_u8
      @raw_data[1] = @length

      @raw_data[TUNNEL_TAG_INDEX] = ((tag & 0xFF) == 0) ? 0x00.to_u8 : tag

        Utils.to_3bytes(@tunnel_medium_type.to_i32)
          .copy_to @raw_data[TUNNEL_TYPE_VALUE_INDEX], TUNNEL_TYPE_LENGTH
    end
  end
end
