
module Radius
  class Client
    private DEFAULT_RETRIES = 3
    private DEFAULT_AUTH_PORT = 1812_u32
    private DEFAULT_ACCT_PORT = 1813_u32
    private DEFAULT_SOCKET_TIMEOUT = 3000

    private shared_secret = String.empty
    private host_name = String.empty

    private getter host_name
    private getter shared_secret
    private getter sock_timeout
    private getter auth_port
    private getter acct_port
    private getter local_end_point

    def initialize(
      @host_name,
      @shared_secret,
      @sock_timeout = DEFAULT_SOCKET_TIMEOUT,
      @auth_port = DEFAULT_AUTH_PORT,
      @acct_port = DEFAULT_ACCT_PORT,
      @local_end_point = nil
    )
    end

    def authenticate(username, password)
      packet = RadiusPacket.new(RadiusCode.ACCESS_REQUEST)
      packet.authenticate = @shared_secret
      encrypted_pass = Utils.encoded_pap_password(password.to_slice, packet.autheticator, @shared_secret)
      packet.attribute = RadiusAttribute.new(RadisuAttributeType.USER_NAME, username.to_slice)
      packet.attribute = RadiusAttribute.new(RadiusAttributeType.USER_PASSWORD, encrypted_pass)
      packet
    end

    def send_and_receive_packet(packet, retries = DEFAULT_RETRIES)
    end

    def ping
    end

    def verify_authenticator(requested_packet, receive_packet)
    end

    def verify_accounting_authenticator(radius_packet, secret)
    end
  end
end
