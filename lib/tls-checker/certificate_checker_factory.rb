# frozen_string_literal: true

module TLSChecker
  class CertificateCheckerFactory
    def initialize
      @resolver = Resolv::DNS.new
    end

    def certificate_checkers_for(specification)
      hostname, port, starttls = specification.split(':', 3)

      port = port.to_i if port
      starttls = starttls.to_sym if starttls

      port ||= port_for(hostname)
      starttls ||= starttls_for(port)
      @resolver.getaddresses(hostname).map { |ip| CertificateChecker.new(hostname, ip, port, starttls) }
    end

    private

    def port_for(hostname)
      {
        'smtp.'   => 25,
        'mx.'     => 25,
        'imap.'   => 143,
        'ldap.'   => 389,
        'puppet.' => 8140,
      }.each do |prefix, port|
        return port if hostname.start_with?(prefix)
      end

      443
    end

    def starttls_for(port)
      well_known_starttls = {
        25  => :smtp,
        143 => :imap,
        389 => :ldap,
      }

      starttls = well_known_starttls[port]
      starttls ||= :raw
      starttls
    end
  end
end
