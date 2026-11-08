# frozen_string_literal: true

# harar's client for Ruby:
#
#   require "harar"
#   harar = Harar.vault                                  # the agent on this machine
#   harar.secrets.resolve("harar://prod/shop/STRIPE_KEY") # the key it names
#
# A gateway that attaches keys on their way out asks where each may go, and
# for it for one host only: hosts(secret) and send(secret, host).
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

  # What a reference to a vault key starts with, as op:// for 1Password.
  REFERENCE_PREFIX = "harar://"

  # harar refused, or could not be asked; the message names why.
  class Error < StandardError; end

  # The vault key `value` names, if the whole value is a harar:// reference.
  def self.reference(value)
    return nil unless value.is_a?(String) && value.start_with?(REFERENCE_PREFIX)

    key = value.delete_prefix(REFERENCE_PREFIX)
    key.empty? || key.match?(/\s/) ? nil : key
  end

  # Where the per-user agent (`harar agent`) listens: the harar binary's rule.
  def self.agent_socket
    home = ENV.fetch("HOME", nil)
    runtime = ENV.fetch("XDG_RUNTIME_DIR", nil)
    return File.join(home, "Library/Application Support/harar", "agent.sock") if RUBY_PLATFORM.include?("darwin") && home && !home.empty?
    return File.join(runtime, "harar", "agent.sock") if runtime && !runtime.empty?

    File.join(home.nil? || home.empty? ? "/" : home, ".harar", "agent.sock")
  end

  # harar:// references resolved to their values, the shape of 1Password's
  # client.secrets.resolve("op://..."). Read when asked for; held only by you.
  class Secrets
    # `ask` sends one request to harar and returns its answer.
    def initialize(ask)
      @ask = ask
    end

    # The value `ref` (harar://prod/shop/STRIPE_KEY) names.
    def resolve(ref)
      key = Harar.reference(ref)
      raise Error, "not a harar:// reference: #{ref.inspect}" if key.nil?

      value = @ask.call({ op: "get", key: key }, ref)["value"]
      raise Error, "harar sent no value for #{ref}" unless value.is_a?(String)

      value
    end

    # Each reference's value, in order; the first that fails is the error.
    def resolve_all(refs)
      refs.map { |ref| resolve(ref) }
    end
  end

  # A vault on harar's socket: the secrets its references name, and for a
  # gateway, where each may go and the secret itself for one host only.
  class Vault
    attr_reader :secrets

    def initialize(socket)
      unless socket.is_a?(String) && socket.start_with?("/")
        raise ArgumentError, "Harar.vault(socket:): the socket is an absolute path"
      end

      @socket = socket
      @secrets = Secrets.new(method(:ask))
    end

    # For a gateway: the host patterns `secret` may go to: an exact name, or `*.example.com`
    # for any name under it (never the name itself).
    def hosts(secret)
      hosts = ask({ op: "hosts", key: secret }, secret)["hosts"]
      unless hosts.is_a?(Array) && hosts.all? { |h| h.is_a?(String) }
        raise Error, "harar sent no hosts for #{secret}"
      end

      hosts
    end

    # For a gateway: `secret`'s value, for a request to `host` only. (This is
    # harar's send; Object#send stays reachable as __send__ and public_send.)
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

  # A harar edge service token, as `harar edge token create` makes it.
  EDGE_TOKEN = /\Aharar_edge_[0-9a-f]{16}_[A-Za-z0-9_-]{43}\z/
  # https://, or http:// to this machine only.
  EDGE_URL = %r{\A(https://[^/]|http://(127\.0\.0\.1|localhost|\[::1\])([:/]|\z))}

  # harar:// references resolved at a harar edge, with a service token.
  class EdgeSecrets
    def initialize(edge, token)
      @edge = edge
      @token = token
    end

    # The value `ref` names.
    def resolve(ref)
      resolve_all([ref]).first
    end

    # Each reference's value, in order, in one request: all or nothing.
    def resolve_all(refs)
      refs = refs.to_a
      return [] if refs.empty?

      refs.each { |ref| raise Error, "not a harar:// reference: #{ref.inspect}" if Harar.reference(ref).nil? }
      ask(refs, refs.length == 1 ? refs.first : "#{refs.length} references")
    end

    private

    # One POST of /v1/resolve (docs/edge.md), all or nothing.
    def ask(refs, what)
      status, body = post(JSON.generate({ refs: refs }))
      begin
        answer = JSON.parse(body)
      rescue JSON::ParserError
        raise Error, "harar at #{@edge} did not answer with JSON (#{status})"
      end
      raise Error, "harar at #{@edge} did not answer with an object" unless answer.is_a?(Hash)

      unless (200..299).cover?(status)
        code = answer["error"].is_a?(String) ? answer["error"] : status.to_s
        message = answer["message"].is_a?(String) ? ": #{answer['message']}" : ""
        raise Error, "harar refused #{what}: #{code}#{message}"
      end
      values = answer["values"]
      unless values.is_a?(Array) && values.length == refs.length && values.all? { |v| v.is_a?(String) }
        raise Error, "harar sent no value for #{what}"
      end

      values
    end

    def post(body)
      require "net/http"
      uri = URI("#{@edge}/v1/resolve")
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https", open_timeout: TIMEOUT_S, read_timeout: TIMEOUT_S) do |http|
        request = Net::HTTP::Post.new(uri)
        request["content-type"] = "application/json"
        request["authorization"] = "Bearer #{@token}"
        request.body = body
        http.request(request) do |res|
          text = +""
          res.read_body do |chunk|
            text << chunk
            raise Error, "harar sent too long an answer" if text.bytesize > MAX_ANSWER
          end
          return [res.code.to_i, text.force_encoding(Encoding::UTF_8)]
        end
      end
    rescue Net::OpenTimeout, Net::ReadTimeout
      raise Error, "harar at #{@edge}: did not answer in #{TIMEOUT_S} s"
    rescue SystemCallError, SocketError, IOError, OpenSSL::SSL::SSLError => e
      raise Error, "harar at #{@edge}: #{e.message}"
    end
  end

  # A vault at a harar edge (docs/edge.md): it resolves references, and only
  # those its service token may read. hosts and send are for gateways on
  # harar's local socket.
  class EdgeVault
    attr_reader :secrets

    def initialize(edge, token)
      raise ArgumentError, "Harar.vault(edge:): the edge is an https:// URL" unless edge.is_a?(String) && edge.match?(EDGE_URL)
      unless token.is_a?(String) && token.match?(EDGE_TOKEN)
        raise ArgumentError, "Harar.vault(edge:, token:): the token is a harar edge service token (harar edge token create)"
      end

      @secrets = EdgeSecrets.new(edge.sub(%r{/+\z}, ""), token)
    end
  end

  # harar at `socket`: by default the per-user agent on this machine
  # (`harar agent`), else a primary (/run/harar.sock). Or, with `edge:` and
  # `token:`, a harar edge, for a service off your network: its URL and a
  # service token from `harar edge token create`, read from the platform's
  # secrets.
  def self.vault(socket: nil, edge: nil, token: nil)
    unless edge.nil? && token.nil?
      raise ArgumentError, "Harar.vault: a socket or an edge, not both" unless socket.nil?

      return EdgeVault.new(edge, token)
    end
    Vault.new(socket.nil? ? agent_socket : socket)
  end
end
