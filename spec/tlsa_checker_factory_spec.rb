# frozen_string_literal: true

RSpec.describe TLSChecker::TLSACheckerFactory do
  let(:factory) { TLSChecker::TLSACheckerFactory.new }

  describe '#certificate_checkers_for' do
    let(:certificate_checker) do
      checker = TLSChecker::CertificateChecker.new('mx.blogreen.org', Resolv::IPv6.create('2001:DB8::25'), 25, :smtp)
      checker.instance_variable_set(:@certificate, OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')))
      checker
    end

    before do
      expect(factory.instance_variable_get('@resolver')).to receive(:getresources).with('_25._tcp.mx.blogreen.org.', Resolv::DNS::Resource::IN::ANY).and_call_original
    end

    context '#tlsa_checkers_for' do
      subject { factory.tlsa_checkers_for(certificate_checker) }

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }
    end
  end
end
