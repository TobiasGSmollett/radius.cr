require "openssl"

module Radius
  class Utils
    def self.accounting_request_authenticator(data, shared_secret)
      sum = (data.to_a + szhared_secret).to_slice
      data.copy_to sum[0, data.size]
      shared_s.copy_to sum[data.size, shared_s.size]
      data[4,16] = Slice.empty

      OpenSSL::MD5.hash sum, sum.bytesize
    end

    def self.access_request_authenticator(shared_secret)
      shared_s = shared_secret.to_slice
      request_authenticator = Bytes.new(16 + shared_s.size)

      r = Random.new
      (0..15).each { |i| request_authenticator[i] = r.rand.to_u8 }
      shared_s.copy_to request_authenticator[16, shared_s.size]

      OpenSSL::MD5.hash request_authenticator, request_authenticator.bytesize
    end

    def self.response_authenticator(data, request_authenticator, shared_secret)
      shared_s = shared_secret.to_slice
      sum = Bytes.new(data.size + shared_s.size)

      data.copy_to sum[0, data.size]
      request_authenticator.copy_to sum[4,16]
      shared_s.copy_to sum[data.size, shared_s.size]

      OpenSSL::MD5.hash sum, sum.bytesize
    end

    def self.encode_pap_password(user_pass_bytes, request_authenticator, shared_secret)
      if user_pass_bytes.size > 128
        raise Exception.new("the PAP password cannot be greater than 128 bytes...")
      end

      encrypted_pass =
        if user_pass_bytes.size % 16 == 0
          Bytes.new(user_pass_bytes.size)
        else
          Bytes.new((user_pass_bytes.size / 16) * 16 + 16)
        end

      user_pass_bytes.copy_to encrypted_pass[0, user_pass_bytes.size]

      (user_pass_bytes...encrypted_pass.size).each { |i| encrypted_pass[i] = 0 }

      shared_secret_bytes = shared_secret.to_slice

      (0...(encrypted_pass.size / 16)).each do |chunk|
        hash = OpenSSL::MD5.hash shared_secret_bytes
        (0...16).each do |i|
          j = i + chunk * 16
          encrypted_pass[j] = (hash[i] ^ encrypted_pass[j]).to_slice
        end
      end

      encrypted_pass
    end

    def self.to_3bytes(val : UInt32)
      Bytes.new(3){
        (val >> 16 & 0xff),
        (val >>  8 & 0xff),
        (val       & 0xff)
      }
    end

    def self.to_3bytes(val : Int32)
      Utils.to_3bytes val.to_u32
    end

    def self.three_bytes_to_uint(bytes, offset)
      ( bytes[offset + 2] << 16
      | bytes[offset + 1] << 8
      | bytes[offset] )
    end

    def get_network_bytes(value)
      size = sizeof(typeof(value))
      result = Bytes.new(size)
      (0...size).each do |i|
        result[-i + size - 1] = (value & 0xff)
        value = (value >> 8)
      end
      result
    end
  end
end
