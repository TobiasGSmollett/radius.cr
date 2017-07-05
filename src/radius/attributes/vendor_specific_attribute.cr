
module Radius
  class VendorSpecificAttribute < RadiusAttribute
    private VSA_ID_INDEX = 2_u32
    private VSA_TYPE_INDEX = 6_u8
    private VSA_LENGTH_INDEX = 7_u8
    private VSA_DATA_INDEX = 8_u8

    @vendor_specific_type : UInt8

    def initialize(@vendor_id, @vendor_specific_type, vendor_specific_data)
      super AttributeType::VENDOR_SPECIFIC
      @data = vendor_specific_data
      @length = (@data.size + VSA_DATA_INDEX).to_u8
      @raw_data = Bytes.new @length
      @raw_data[0] = @type
      @raw_data[1] = @length

      vendor_id_array = @vendor_id.to_slice
      vendor_id_array.reverse!
      @raw_data.copy_from vendor_id_array[ATTRIBUTE_HEADER_SIZE, sizeof(UInt32)]

      @raw_data[VSA_TYPE_INDEX] = @vendor_specific_type
      @raw_data[VSA_LENGTH_INDEX] = (@data.size + ATTRIBUTE_HEADER_SIZE).to_u8

      @raw_data.copy_from vendor_specific_data[VSA_DATA_INDEX, vendor_specific_data.size]
    end

    def initialize(raw_data, offset)
      super AttributeType::VENDOR_SPECIFIC
      vendor_id_array = Bytes.new sizeof(UInt32)
      #vendor_id_array.copy_from
      vendor_id_array.reverse!
      @vendor_id = 0#vendor_id_array.to_u32

      @vendor_specific_type = raw_data[VSA_TYPE_INDEX + offset]
      vendor_specific_length = raw_data[VSA_LENGTH_INDEX + offset]

      @data = Bytes.new(vendor_specific_length - 2)
      # Array copy
      @length = (@data.size + VSA_DATA_INDEX)

      @raw_data = raw_data[0, vendor_specific_length]
    end

  end
end
