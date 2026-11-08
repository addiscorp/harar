# frozen_string_literal: true

# The client against a stand-in harar on a unix socket: the requests it
# sends are the ones harar's `hosts` and `send` take (the harar crate's
# PrimaryRequest::Hosts { key } and Send { key, host }, tag "op"), and every
# way harar can say no is an error naming why. The same cases as js/test.
require "minitest/autorun"
require "fileutils"
require "json"
require "socket"
require "tmpdir"
require_relative "../lib/harar"

class VaultTest < Minitest::Test
  # A stand-in harar answering each request with reply.(request).
  def harar(reply)
    dir = Dir.mktmpdir("harar-rb-")
    socket = File.join(dir, "h.sock")
    requests = []
    server = UNIXServer.new(socket)
    thread = Thread.new do
      loop do
        conn = server.accept
        request = JSON.parse(conn.read)
        requests << request
        begin
          conn.write(reply.call(request))
        rescue SystemCallError
          nil # the client stopped reading: too long an answer
        end
        conn.close
      end
    rescue IOError
      nil # the server closed
    end
    yield socket, requests
  ensure
    server&.close
    thread&.join
    FileUtils.remove_entry(dir) if dir
  end

  STRIPE = lambda do |r|
    if r["op"] == "hosts"
      JSON.generate(ok: true, hosts: ["api.stripe.com", "*.stripe.com"])
    elsif r["op"] == "send" && r["host"] == "api.stripe.com"
      JSON.generate(ok: true, value: "sk_live_real")
    else
      JSON.generate(ok: false, error: "not_allowed")
    end
  end

  def test_hosts_and_send_ask_harar_exactly_and_a_send_is_for_one_host
    harar(STRIPE) do |socket, requests|
      v = Harar.vault(socket: socket)
      assert_equal ["api.stripe.com", "*.stripe.com"], v.hosts("prod/shop/STRIPE_KEY")
      assert_equal "sk_live_real", v.send("prod/shop/STRIPE_KEY", "api.stripe.com")
      e = assert_raises(Harar::Error) { v.send("prod/shop/STRIPE_KEY", "evil.example.com") }
      assert_match %r{harar refused prod/shop/STRIPE_KEY to evil\.example\.com: not_allowed}, e.message
      assert_equal [
        { "op" => "hosts", "key" => "prod/shop/STRIPE_KEY" },
        { "op" => "send", "key" => "prod/shop/STRIPE_KEY", "host" => "api.stripe.com" },
        { "op" => "send", "key" => "prod/shop/STRIPE_KEY", "host" => "evil.example.com" }
      ], requests
    end
  end

  def test_every_way_harar_can_fail_is_an_error_naming_why
    [
      ["not json", /did not answer with JSON/],
      ["null", /did not answer with an object/],
      ["[1]", /did not answer with an object/],
      [JSON.generate(ok: true), /no value|no hosts/],
      [JSON.generate(ok: false, error: "locked"), /harar refused .*: locked/],
      ["x" * (1024 * 1024 + 1), /too long an answer/]
    ].each do |answer, why|
      harar(->(_) { answer }) do |socket, _|
        v = Harar.vault(socket: socket)
        assert_match why, assert_raises(Harar::Error) { v.send("a/b", "x.example.com") }.message
        assert_match why, assert_raises(Harar::Error) { v.hosts("a/b") }.message
      end
    end
    e = assert_raises(Harar::Error) { Harar.vault(socket: "/nonexistent/h.sock").hosts("a/b") }
    assert_match %r{harar at /nonexistent/h\.sock}, e.message
    assert_match(/absolute path/, assert_raises(ArgumentError) { Harar.vault(socket: "relative.sock") }.message)
  end

  def test_secrets_resolve_reads_the_key_a_harar_reference_names
    values = { "prod/shop/STRIPE_KEY" => "sk_live_real", "prod/shop/OTHER" => "other" }
    answer = lambda do |r|
      if values.key?(r["key"])
        JSON.generate(ok: true, value: values[r["key"]])
      else
        JSON.generate(ok: false, error: "not_found")
      end
    end
    harar(answer) do |socket, requests|
      v = Harar.vault(socket: socket)
      assert_equal "sk_live_real", v.secrets.resolve("harar://prod/shop/STRIPE_KEY")
      assert_equal %w[sk_live_real other], v.secrets.resolve_all(%w[harar://prod/shop/STRIPE_KEY harar://prod/shop/OTHER])
      e = assert_raises(Harar::Error) { v.secrets.resolve("harar://prod/shop/GONE") }
      assert_match %r{harar refused harar://prod/shop/GONE: not_found}, e.message
      # Not a reference: refused before harar is asked anything.
      ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b", nil].each do |not_one|
        assert_match %r{not a harar:// reference}, assert_raises(Harar::Error) { v.secrets.resolve(not_one) }.message
      end
      assert_equal [
        { "op" => "get", "key" => "prod/shop/STRIPE_KEY" },
        { "op" => "get", "key" => "prod/shop/STRIPE_KEY" },
        { "op" => "get", "key" => "prod/shop/OTHER" },
        { "op" => "get", "key" => "prod/shop/GONE" }
      ], requests
    end
  end

  def test_vault_with_no_socket_asks_the_agent_where_harar_agent_listens
    saved = ENV.to_h.slice("HOME", "XDG_RUNTIME_DIR")
    ENV["HOME"] = "/home/someone"
    ENV["XDG_RUNTIME_DIR"] = "/run/user/1000"
    darwin = RUBY_PLATFORM.include?("darwin")
    want = darwin ? "/home/someone/Library/Application Support/harar/agent.sock" : "/run/user/1000/harar/agent.sock"
    assert_equal want, Harar.agent_socket
    e = assert_raises(Harar::Error) { Harar.vault.secrets.resolve("harar://a/b") }
    assert e.message.start_with?("harar at #{want}:"), e.message
    ENV.delete("XDG_RUNTIME_DIR")
    assert_equal "/home/someone/.harar/agent.sock", Harar.agent_socket unless darwin
  ensure
    %w[HOME XDG_RUNTIME_DIR].each { |k| saved&.key?(k) ? ENV[k] = saved[k] : ENV.delete(k) }
  end
end
