# frozen_string_literal: true

RSpec.describe TLSChecker::TLSACheckerFactory do
  let(:factory) { described_class.new }

  describe '#certificate_checkers_for' do
    let(:certificate_checker) do
      checker = TLSChecker::CertificateChecker.new('mx.blogreen.org', Resolv::IPv6.create('2001:db8::25'), 25, :smtp)
      checker.instance_variable_set(:@certificate, OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')))
      checker
    end
    let(:resolver) { factory.instance_variable_get('@resolver') }

    before do
      allow(resolver).to receive(:getresources).with('_25._tcp.mx.blogreen.org.', Resolv::DNS::Resource::IN::ANY).and_call_original
    end

    describe '#tlsa_checkers_for' do
      subject { factory.tlsa_checkers_for(certificate_checker) }

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }
    end
  end
end
