# frozen_string_literal: true

RSpec.describe TLSChecker::TLSAChecker do
  let(:tlsa_checker) { described_class.new(record, certificate_checker) }

  let(:record) do
    Resolv::DNS::Resource::IN::TLSA.new(3, 1, 1, 'd8aac0d602e5532136ffb9e368fbc3c9a7a4b694340800b08731bcc09099a925')
  end

  let(:certificate_checker) do
    checker = TLSChecker::CertificateChecker.new('mx.blogreen.org', Resolv::IPv6.create('2001:db8::25'), 25, :smtp)
    checker.instance_variable_set(:@certificate, OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')))
    checker
  end

  describe '#to_e' do
    subject { tlsa_checker.to_e }

    it { is_expected.to include(state: 'ok') }
    it { is_expected.to include(service: %r{X.509/mx\.blogreen\.org/\[2001:db8::25\]:25/TLSA}i) }
  end
end
