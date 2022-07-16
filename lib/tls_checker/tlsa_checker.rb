# frozen_string_literal: true

module TLSChecker
  class TLSAChecker < InternetSecurityEvent::TLSAStatus
    def initialize(record, certificate_checker)
      super(record, certificate_checker.certificate)

      @certificate_checker = certificate_checker
    end

    def to_e
      super.merge(
        service: service,
        ttl:     12.hours,
      )
    end

    private

    def service
      "#{@certificate_checker.service}/TLSA"
    end
  end
end
