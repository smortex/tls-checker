# frozen_string_literal: true

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

      it 'returns the ipaddress as a string' do
        expect(subject.send(:humanized_address)).to eq('128.66.0.1')
      end
    end

    context 'with IPv6' do
      it 'returns the ipaddress as a string with square brackets' do
        expect(subject.send(:humanized_address)).to eq('[2001:DB8::1]')
      end
    end
  end

  context '#certificate' do
    subject do
      TLSChecker::CertificateCheckerFactory.new.certificate_checkers_for(specification).first
    end

    context 'connecting to a TLS service' do
      let(:specification) { 'opus-labs.fr' }

      it 'fetches a certificate' do
        expect(subject.send(:certificate)).to be_a(OpenSSL::X509::Certificate)
      end
    end

    context 'connecting to an IMAP server' do
      let(:specification) { 'imap.opus-labs.fr' }

      it 'fetches a certificate' do
        expect(subject.send(:certificate)).to be_a(OpenSSL::X509::Certificate)
      end
    end

    context 'connecting to a LDAP server' do
      let(:specification) { 'ldap.opus-labs.fr' }

      it 'fetches a certificate' do
        expect(subject.send(:certificate)).to be_a(OpenSSL::X509::Certificate)
      end
    end

    context 'connecting to a SMTP server' do
      let(:specification) { '127.0.0.1:2525:smtp' }
      subject do
        TLSChecker::CertificateChecker.new('random.fqdn', '127.0.0.1', 2525, :smtp)
      end

      before do
        logger = Logger.new(STDOUT)
        logger.level = Logger::WARN
        @server = MidiSmtpServer::Smtpd.new(2525, '127.0.0.1', 4, tls_mode: :TLS_OPTIONAL, logger: logger)
        @server.start
      end

      after do
        @server.stop
      end

      it 'fetches a certificate' do
        expect(subject.send(:certificate)).to be_a(OpenSSL::X509::Certificate)
      end
    end
  end
end
