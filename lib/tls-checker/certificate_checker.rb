# frozen_string_literal: true

require 'openssl'
require 'resolv'
require 'net/ldap'
require 'internet_security_event'

module TLSChecker
  class CertificateChecker
    include ActionView::Helpers::DateHelper

    def initialize(hostname, address, port, starttls)
      @hostname = hostname
      @address = address
      @port = port
      @starttls = starttls

      @certificate = nil
      @certificate_failure = nil
      @tls_socket = nil
    end

    attr_reader :hostname, :address, :port, :starttls

    def to_e
      if certificate
        InternetSecurityEvent::TLSStatus.build(hostname, certificate)
      else
        {
          state:       'critical',
          description: @certificate_failure || "#{hostname} does not have a valid certificate",
        }
      end.merge(
        service: service,
        ttl:     3600 * 12,
        tags:    ['tls-checker'],
      )
    end

    def to_s
      description
    end

    private

    def service
      format('X.509/%<hostname>s/%<address>s:%<port>d', hostname: hostname, address: humanized_address, port: port)
    end

    def humanized_address
      if @address.is_a?(Resolv::IPv6)
        "[#{@address}]"
      else
        @address.to_s
      end
    end

    def certificate
      @certificate = OpenSSL::X509::Certificate.new(tls_socket.peer_cert) if @certificate.nil?
      @certificate
    rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::LDAP::ConnectionRefusedError, SocketRecvTimeout => e
      @certificate_failure = e.message
      @certificate = false
    end

    def tls_socket
      @tls_socket ||= case starttls
                      when :smtp
                        smtp_socket
                      when :imap
                        imap_socket
                      when :ldap
                        ldap_socket
                      else
                        basic_socket
                      end
    end

    def basic_socket
      ssl_socket = OpenSSL::SSL::SSLSocket.new(TCPSocket.new(@address.to_s, port), ssl_context)
      ssl_socket.hostname = hostname
      begin
        ssl_socket.connect
      rescue OpenSSL::SSL::SSLError # rubocop:disable Lint/HandleExceptions
        # This may fail for example if a client certificate is required
      end
      ssl_socket
    end

    def imap_socket
      socket = LineOrientedSocket.new(@address.to_s, port)
      socket.gets_until_match(/^\* OK/)
      socket.puts('. CAPABILITY')
      socket.gets_until_match(/^\. OK/)
      socket.puts('. STARTTLS')
      socket.gets_until_match(/^\. OK/)

      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
      ssl_socket.connect
      ssl_socket
    end

    def ldap_socket
      ldap = Net::LDAP.new(host: @address.to_s, port: port, encryption: { method: :start_tls, tls_options: tls_options })

      ldap.open do |conn|
        return conn.instance_variable_get(:@open_connection).instance_variable_get(:@conn)
      end
    end

    def smtp_socket
      socket = LineOrientedSocket.new(@address.to_s, port)
      socket.gets_until_match(/^220 /)
      socket.puts("EHLO #{my_hostname}")
      socket.gets_until_match(/^250 /)
      socket.puts('STARTTLS')
      socket.gets

      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
      ssl_socket.connect
      ssl_socket
    end

    def my_hostname
      Socket.gethostbyname(Socket.gethostname).first
    rescue SocketError
      Socket.gethostname
    end

    def ssl_context
      ssl_context = OpenSSL::SSL::SSLContext.new
      # We do not care about trust here, only expiration dates.

      #  ____              _ _                                                 _
      # |  _ \  ___  _ __ ( ) |_    ___ ___  _ __  _   _       _ __   __ _ ___| |_ ___
      # | | | |/ _ \| '_ \|/| __|  / __/ _ \| '_ \| | | |_____| '_ \ / _` / __| __/ _ \
      # | |_| | (_) | | | | | |_  | (_| (_) | |_) | |_| |_____| |_) | (_| \__ \ ||  __/
      # |____/ \___/|_| |_|  \__|  \___\___/| .__/ \__, |     | .__/ \__,_|___/\__\___|
      #                                     |_|    |___/      |_|
      #  _   _     _     _
      # | |_| |__ (_)___| |
      # | __| '_ \| / __| |
      # | |_| | | | \__ \_|
      #  \__|_| |_|_|___(_)
      #
      # YOU SHALL  NOT  "COPY-PASTE"  THE FOLLOWING LINE  IN YOUR CODE.  IF YOU
      # UNDESTAND WHY WE DO TAHT,  YOU KNOW WHY YOU DON'T WANT TO DO THIS.   IF
      # YOU DO NOT UNDERSTAND WHAT IT DOES,  REALIZE THAT YOUR PROBLEM VANISHED
      # WHEN YOU PASTE IT AND SHIP IT, FEL FREE TO GET BACK TO ME WHEN YOU WILL
      # DISCOVER THAT YOU HAVE WAY  MORE PROBLEMS  THAN YOU THOUGH.   I WILL BE
      # PLEASED TO  EXCHANGE MONEY WITH ADVICES AND ASSISTANCE  FOR FIXING YOUR
      # PROBLEMS.
      ssl_context.set_params(tls_options)
      ssl_context
    end

    def tls_options
      {
        verify_mode: OpenSSL::SSL::VERIFY_NONE,
      }
    end
  end
end
