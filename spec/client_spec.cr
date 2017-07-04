require "./spec_helper"

Mocks.create_mock Radius::Client do
  mock send_and_receive_packet(packet, retries = 3)
end

describe Radius::Client do
  before { Mocks.reset }

  it "ping" do
    client_mock = Radius::Client.new "localhost", "aaa"
    input = Radius::RadiusPacket.new(Radius::RadiusCode::SERVER_STATUS, 1_u8)

    allow(client_mock)
      .to receive(send_and_receive_packet(input))
      .and_return("aaa")

    true.should eq (client_mock.ping == "aaa")
  end

end
