
module Radius
  class Client
    private DEFAULT_RETRIES = 3
    private DEFAULT_AUTH_PORT = 1812
    private DEFAULT_ACCT_PORT = 1813
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

    def authentivate(username, password)

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
