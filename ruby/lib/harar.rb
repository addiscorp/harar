# frozen_string_literal: true

# harar's client for Ruby:
#
#   require "harar"
#   v = Harar.vault(socket: "/run/harar.sock")
#   v.hosts("prod/shop/STRIPE_KEY")                   # ["api.stripe.com"]
#   v.send("prod/shop/STRIPE_KEY", "api.stripe.com")  # the key, for that host only
#
# One JSON request on harar's local socket, the write side closed, one JSON
# answer: the protocol the per-user agent and a primary both speak. harar
# decides every send, and records the host; this client holds nothing.
require "io/wait"
require "json"
require "socket"
require_relative "harar/version"

module Harar
  # harar's answers are small; anything longer is refused.
  MAX_ANSWER = 1024 * 1024
  # How long harar has to answer (a per-user agent may be asking for Touch ID).
  TIMEOUT_S = 60

  # harar refused, or could not be asked; the message names why.
  class Error < StandardError; end

  # A vault on harar's socket: where each secret may go, and the secret
  # itself for one host only.
  class Vault
    def initialize(socket)
      unless socket.is_a?(String) && socket.start_with?("/")
        raise ArgumentError, "Harar.vault(socket:): the socket is an absolute path"
      end

      @socket = socket
    end

    # The host patterns `secret` may go to: an exact name, or `*.example.com`
    # for any name under it (never the name itself).
    def hosts(secret)
      hosts = ask({ op: "hosts", key: secret }, secret)["hosts"]
      unless hosts.is_a?(Array) && hosts.all? { |h| h.is_a?(String) }
        raise Error, "harar sent no hosts for #{secret}"
      end

      hosts
    end

    # `secret`'s value, for a request to `host` only. harar decides, and
    # records the host. (This is harar's send; Object#send stays reachable
    # as __send__ and public_send.)
    def send(secret, host)
      value = ask({ op: "send", key: secret, host: host }, "#{secret} to #{host}")["value"]
      raise Error, "harar refused #{secret} to #{host}: no value" unless value.is_a?(String)

      value
    end

    private

    # One request to harar, and its answer if it says ok; otherwise why not.
    def ask(request, what)
      body = read_answer(JSON.generate(request))
      begin
        answer = JSON.parse(body)
      rescue JSON::ParserError
        raise Error, "harar at #{@socket} did not answer with JSON"
      end
      raise Error, "harar at #{@socket} did not answer with an object" unless answer.is_a?(Hash)
      return answer if answer["ok"] == true

      error = answer["error"]
      raise Error, "harar refused #{what}: #{error.is_a?(String) ? error : 'no answer'}"
    end

    def read_answer(request)
      UNIXSocket.open(@socket) do |conn|
        conn.write(request)
        conn.close_write
        body = +""
        loop do
          raise Error, "harar did not answer in #{TIMEOUT_S} s" unless conn.wait_readable(TIMEOUT_S)

          chunk = conn.read_nonblock(65_536, exception: false)
          break if chunk.nil?
          next if chunk == :wait_readable

          body << chunk
          raise Error, "harar sent too long an answer" if body.bytesize > MAX_ANSWER
        end
        body.force_encoding(Encoding::UTF_8)
      end
    rescue SystemCallError => e
      raise Error, "harar at #{@socket}: #{e.message}"
    end
  end

  # harar at `socket`: a per-user agent or a primary.
  def self.vault(socket:)
    Vault.new(socket)
  end
end
