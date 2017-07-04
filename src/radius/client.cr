require "socket"

module Radius
  class Client
    private DEFAULT_RETRIES = 3
    private DEFAULT_AUTH_PORT = 1812_u32
    private DEFAULT_ACCT_PORT = 1813_u32
    private DEFAULT_SOCKET_TIMEOUT = 3000

    private getter host_name
    private getter shared_secret

    private getter host_name
    private getter shared_secret
    private getter sock_timeout
    private getter auth_port
    private getter acct_port

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
      udp.socket.read_timeout = sock_timeout
      host_ip = nil

      begin
        udp_socket.bind local_end_point, auth_port.to_i32 if !local_end_point.nil?
        host_ip = Socket::IPAddress.new(host_name, auth_port.to_i32)

        raise Exception.new "Resulving " + host_name + " returned no hists in DNS" if host_ip.nil?
      end

      number_of_attempts = 0

      while number_of_attempts < retries
        begin
          udp_socket.send packet.raw_data
          message, addr = udp_socket.receive
          received_packet = RadiusPacket.new message
          return received_packet if received_packet.valid
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
        result = send_and_receive_packet auth_packet, 0
        channel.send result
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
