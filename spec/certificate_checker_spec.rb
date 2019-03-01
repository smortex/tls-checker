# frozen_string_literal: true

require 'logger'
require 'midi-smtp-server'

RSpec.describe TLSChecker::CertificateChecker do
  subject do
    TLSChecker::CertificateChecker.new(hostname, address, port, starttls)
  end

  let(:hostname) do
    'example.com'
  end

  let(:certificate_hostname) { hostname }

  let(:address) do
    Resolv::IPv6.create('2001:DB8::1')
  end

  let(:port) { 443 }
  let(:starttls) { :raw }

  context '#humanized_address' do
    context 'with IPv4' do
      let(:address) { Resolv::IPv4.create('128.66.0.1') }

      it { is_expected.to have_attributes(humanized_address: '128.66.0.1') }
    end

    context 'with IPv6' do
      it { is_expected.to have_attributes(humanized_address: '[2001:DB8::1]') }
    end
  end

  context '#certificate' do
    let(:checker) { TLSChecker::CertificateCheckerFactory.new.certificate_checkers_for(specification).first }
    subject { checker.certificate }

    context 'when connecting to a TLS service' do
      let(:specification) { 'opus-labs.fr' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to an IMAP server' do
      let(:specification) { 'imap.opus-labs.fr' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to a LDAP server' do
      let(:specification) { 'ldap.opus-labs.fr' }

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end

    context 'when connecting to a SMTP server' do
      let(:specification) { '127.0.0.1:2525:smtp' }
      let(:checker) { TLSChecker::CertificateChecker.new('random.fqdn', '127.0.0.1', 2525, :smtp) }

      before do
        logger = Logger.new(STDOUT)
        logger.level = Logger::WARN
        @server = MidiSmtpServer::Smtpd.new(2525, '127.0.0.1', 4, tls_mode: :TLS_OPTIONAL, logger: logger)
        @server.start
      end

      after do
        @server.stop
      end

      it { is_expected.to be_an(OpenSSL::X509::Certificate) }
    end
  end
end
