# frozen_string_literal: true

# The client against a stand-in harar edge over HTTP: what it sends is the
# edge's POST /v1/resolve (docs/edge.md §5) with the service token, and every
# way the edge can say no is an error naming why. The same cases as
# js/test/edge.test.js.
require "minitest/autorun"
require "json"
require "socket"
require "harar"

class EdgeTest < Minitest::Test
  TOKEN = "harar_edge_0123456789abcdef_#{'A' * 43}"
  VALUES = { "harar://prod/shop/STRIPE_KEY" => "sk_live_real", "harar://prod/shop/OTHER" => "other" }.freeze

  STRIPE = lambda do |body|
    refs = body["refs"]
    if refs.all? { |r| VALUES.key?(r) }
      [200, JSON.generate({ values: refs.map { |r| VALUES[r] } })]
    else
      [403, JSON.generate({ error: "not_allowed", message: "this caller may not read prod/site/DATABASE_URL" })]
    end
  end

  # A stand-in edge, mounted under /functions/v1/harar-edge as on Supabase:
  # a plain HTTP/1.1 server on a TCPServer, one request per connection.
  class Edge
    attr_reader :url, :requests

    def initialize(reply)
      @requests = []
      @server = TCPServer.new("127.0.0.1", 0)
      @url = "http://127.0.0.1:#{@server.addr[1]}/functions/v1/harar-edge/"
      @thread = Thread.new do
        loop do
          conn = @server.accept
          serve(conn, reply)
        rescue IOError, SystemCallError
          break
        end
      end
    end

    def serve(conn, reply)
      method, path = conn.gets.split(" ")
      headers = {}
      while (line = conn.gets) && line != "\r\n"
        name, value = line.split(":", 2)
        headers[name.downcase] = value.strip
      end
      body = JSON.parse(conn.read(headers["content-length"].to_i))
      @requests << { method: method, url: path, auth: headers["authorization"], type: headers["content-type"], body: body }
      status, text = reply.call(body)
      conn.write("HTTP/1.1 #{status} X\r\ncontent-type: application/json\r\ncontent-length: #{text.bytesize}\r\nconnection: close\r\n\r\n")
      conn.write(text)
    rescue IOError, SystemCallError
      nil # the client stopped reading: too long an answer
    ensure
      conn.close
    end

    def stop
      @server.close
      @thread.join
    end
  end

  def with_edge(reply)
    edge = Edge.new(reply)
    yield edge
  ensure
    edge&.stop
  end

  def test_an_edge_vault_resolves_with_one_post_of_v1_resolve_the_service_token_as_its_bearer
    with_edge(STRIPE) do |e|
      v = Harar.vault(edge: e.url, token: TOKEN)
      assert_equal "sk_live_real", v.secrets.resolve("harar://prod/shop/STRIPE_KEY")
      assert_equal %w[sk_live_real other], v.secrets.resolve_all(["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"])
      assert_equal [], v.secrets.resolve_all([])
      error = assert_raises(Harar::Error) { v.secrets.resolve("harar://prod/site/DATABASE_URL") }
      assert_match %r{harar refused harar://prod/site/DATABASE_URL: not_allowed: this caller may not read}, error.message
      ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", nil].each do |not_one|
        error = assert_raises(Harar::Error) { v.secrets.resolve(not_one) }
        assert_match %r{not a harar:// reference}, error.message
      end
      error = assert_raises(Harar::Error) { v.secrets.resolve_all(["harar://prod/shop/OTHER", "nope"]) }
      assert_match %r{not a harar:// reference: "nope"}, error.message
      expect = ->(refs) { { method: "POST", url: "/functions/v1/harar-edge/v1/resolve", auth: "Bearer #{TOKEN}", type: "application/json", body: { "refs" => refs } } }
      assert_equal [
        expect.call(["harar://prod/shop/STRIPE_KEY"]),
        expect.call(["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]),
        expect.call(["harar://prod/site/DATABASE_URL"]),
      ], e.requests
      refute v.respond_to?(:hosts), "an edge vault has no hosts"
      refute v.public_methods(false).include?(:send), "an edge vault has no harar send"
    end
  end

  def test_every_way_an_edge_can_fail_is_an_error_naming_why_and_the_token_is_never_in_it
    [
      [200, "not json", /did not answer with JSON \(200\)/],
      [502, "<html>bad gateway</html>", /did not answer with JSON \(502\)/],
      [200, "[1]", /did not answer with an object/],
      [200, JSON.generate({ values: [] }), /no value for/],
      [200, JSON.generate({ values: [7] }), /no value for/],
      [401, JSON.generate({ error: "revoked", message: "this token was revoked" }), /harar refused .*: revoked: this token was revoked/],
      [500, JSON.generate({}), /harar refused .*: 500/],
      [200, "x" * ((1024 * 1024) + 1), /too long an answer/],
    ].each do |status, text, why|
      with_edge(->(_) { [status, text] }) do |e|
        error = assert_raises(Harar::Error) { Harar.vault(edge: e.url, token: TOKEN).secrets.resolve("harar://a/b") }
        assert_match why, error.message
        refute_includes error.message, TOKEN[28..]
      end
    end
    error = assert_raises(Harar::Error) { Harar.vault(edge: "http://127.0.0.1:1", token: TOKEN).secrets.resolve("harar://a/b") }
    assert_match %r{\Aharar at http://127.0.0.1:1: }, error.message
  end

  def test_an_edge_is_https_its_token_a_harar_edge_token_and_it_is_one_or_the_other
    assert_match %r{the edge is an https:// URL}, assert_raises(ArgumentError) { Harar.vault(edge: "http://edge.example", token: TOKEN) }.message
    assert_match %r{the edge is an https:// URL}, assert_raises(ArgumentError) { Harar.vault(edge: "http://localhost.evil.example", token: TOKEN) }.message
    assert_match(/service token/, assert_raises(ArgumentError) { Harar.vault(edge: "https://edge.example") }.message)
    error = assert_raises(ArgumentError) { Harar.vault(edge: "https://edge.example", token: "sk_live_oops") }
    refute_includes error.message, "sk_live_oops"
    assert_match(/a socket or an edge, not both/, assert_raises(ArgumentError) { Harar.vault(socket: "/run/harar.sock", edge: "https://edge.example", token: TOKEN) }.message)
    assert Harar.vault(edge: "https://harar-edge.you.workers.dev", token: TOKEN).secrets
    assert Harar.vault(edge: "http://localhost:8787", token: TOKEN).secrets
  end
end
