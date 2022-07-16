# frozen_string_literal: true

require 'logger'
require 'midi-smtp-server'

RSpec.describe TLSChecker::CertificateChecker do
  subject do
    described_class.new(hostname, address, port, starttls)
  end

  let(:hostname) do
    'example.com'
  end

  let(:certificate_hostname) { hostname }

  let(:address) do
    Resolv::IPv6.create('2001:db8::1')
  end

  let(:port) { 443 }
  let(:starttls) { :raw }

  describe '#humanized_address' do
    context 'with IPv4' do
      let(:address) { Resolv::IPv4.create('128.66.0.1') }

      it { is_expected.to have_attributes(humanized_address: '128.66.0.1') }
    end

    context 'with IPv6' do
      it { is_expected.to have_attributes(humanized_address: /[2001:db8::1]/i) }
    end
  end

  describe '#certificate' do
    subject { checker.certificate }

    let(:checker) { TLSChecker::CertificateCheckerFactory.new.certificate_checkers_for(specification).first }

    context 'when connecting to a TLS service' do
      let(:specification) { 'opus-labs.fr' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to an IMAP server' do
      let(:specification) { 'imap.opus-labs.fr' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to a LDAP server' do
      let(:specification) { 'ldap.blogreen.org' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to a SMTP server' do
      let(:specification) { '127.0.0.1:2525:smtp' }
      let(:checker) { described_class.new('random.fqdn', '127.0.0.1', 2525, :smtp) }
      let(:server) { MidiSmtpServer::Smtpd.new(ports: 2525, hosts: '127.0.0.1', tls_mode: :TLS_OPTIONAL, logger_severity: :error) }

      before do
        server.start
      end

      after do
        server.stop
      end

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end
  end
end
