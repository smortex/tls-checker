# frozen_string_literal: true

RSpec.describe TLSChecker::TLSACheckerFactory do
  subject do
    TLSChecker::TLSACheckerFactory.new
  end

  describe '#certificate_checkers_for' do
    let(:certificate_checker) do
      checker = TLSChecker::CertificateChecker.new('mx.blogreen.org', Resolv::IPv6.create('2001:DB8::25'), 25, :smtp)
      checker.instance_variable_set(:@certificate, OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')))
      checker
    end

    before do
      expect(subject.instance_variable_get('@resolver')).to receive(:getresources).with('_25._tcp.mx.blogreen.org.', Resolv::DNS::Resource::IN::ANY).and_call_original
    end

    it '' do
      result = subject.tlsa_checkers_for(certificate_checker)

      expect(result.size).to eq(1)
    end
  end
end
