require "./spec_helper"
require "mocks"

Mocks.create_mock Radius::Client do
  mock send_and_receive_packet(packet)
end

describe Radius::Client do
  before { Mocks.reset }

  it "ping" do
    client_mock = Radius::Client.new "127.0.0.1", 8080

    allow(client_mock)
      .to receive(send_and_receive_packet(RadiusPacket.new(RadiusCode::SERVER_STATUS)))
      .and_return("aaa")

    true.should eq (client_mock.ping == "aaa")
  end

end
