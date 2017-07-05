require "socket"

module Radius
  class Client
    private DEFAULT_RETRIES = 3
    private DEFAULT_AUTH_PORT = 1812
    private DEFAULT_ACCT_PORT = 1813
    private DEFAULT_SOCKET_TIMEOUT = 3000

    private getter host_name : String
    private getter shared_secret : String
    private getter sock_timeout : Int32
    private getter auth_port : Int32
    private getter acct_port : Int32

    def initialize(
      @host_name,
      @shared_secret,
      @sock_timeout = DEFAULT_SOCKET_TIMEOUT,
      @auth_port = DEFAULT_AUTH_PORT,
      @acct_port = DEFAULT_ACCT_PORT
    )
    end

    def authenticate(username, password)
      packet = RadiusPacket.new(RadiusCode::ACCESS_REQUEST)
      packet.authenticate = @shared_secret
      encrypted_pass = Utils.encoded_pap_password(password.to_slice, packet.autheticator, @shared_secret)
      packet.attribute = RadiusAttribute.new(RadisuAttributeType::USER_NAME, username.to_slice)
      packet.attribute = RadiusAttribute.new(RadiusAttributeType::USER_PASSWORD, encrypted_pass)
      packet
    end

    def send_and_receive_packet(packet, retries = DEFAULT_RETRIES)
      udp_socket = UDPSocket.new
      udp_socket.read_timeout = sock_timeout
      host_ip = nil

      begin
        host_ip = Socket::IPAddress.new(host_name, auth_port.to_i32)
        udp_socket.bind host_name, auth_port.to_i32

        raise Exception.new "Resolving " + host_name + " returned no hists in DNS" if host_ip.nil?
      end

      number_of_attempts = 0

      while number_of_attempts < retries
        begin
          udp_socket.send packet.@raw_data
          message, addr = udp_socket.receive
          received_packet = RadiusPacket.new message.to_slice
          return received_packet if received_packet.@valid
        ensure
          udp_socket.close
        end
      end
    end

    def ping
      auth_packet = RadiusPacket.new(RadiusCode::SERVER_STATUS)
      auth_packet.authenticator = shared_secret
      auth_packet.message_authenticator = shared_secret

      channel = Channel(String).new
      spawn do
        result = send_and_receive_packet auth_packet, 1
        channel.send result.to_s
      end
      channel.receive
    end

    def verify_authenticator(requested_packet, received_packet)
      requested_packet.identifier == received_packet.identifier &&
      received_packet.authenticator == Utils.response_authenticator(
                                              received_packet.raw_data,
                                              requested_packet,
                                              shared_secret
                                            )
    end

    def verify_accounting_authenticator(radius_packet, secret)
      secret_bytes = secret.to_slice
      sum = Bytes.new(radius_packet.length + secret_bytes.length)
      authenticator = Bytes.new(16)
      authenticator.copy_from radius_packet[4,16]
      sum.copy_from radius_packet
      secret_bytes.copy_from radius_packet, secret_bytes.length
      sum[4,16] = 0
      authenticator == OpenSSL::MD5.hash(sum)
    end
  end
end
