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
    end
  end
end
