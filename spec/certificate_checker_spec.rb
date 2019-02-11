# frozen_string_literal: true

RSpec.describe CertificateChecker do
  subject do
    CertificateChecker.new(hostname, address, port, starttls)
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

  context '#to_e' do
    let(:not_before) { Time.now - 3600 * 24 }
    let(:not_after) { Time.now + 3600 * 24 * 30 }

    let(:certificate) do
      cert = OpenSSL::X509::Certificate.new
      cert.subject = OpenSSL::X509::Name.parse("/CN=#{certificate_hostname}")
      cert.not_before = not_before
      cert.not_after = not_after
      cert
    end

    before do
      allow(subject).to receive(:certificate).and_return(certificate)
    end

    context 'with a valid certificate' do
      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('ok')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate will expire in about 1 month')
      end

      it 'service is correct' do
        expect(subject.to_e[:service]).to eq('X.509/example.com/[2001:DB8::1]:443')
      end
    end

    context 'with a certificate about to expire' do
      let(:not_after) { Time.now + 3600 * 24 * 5 }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('warn')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate will expire in 5 days')
      end
    end

    context 'with a certificate expiring really soon' do
      let(:not_after) { Time.now + 3600 * 12 }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('critical')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate will expire in about 12 hours')
      end
    end

    context 'with a not valid yet certificate' do
      let(:not_before) { Time.now + 3600 }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('critical')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate will become valid in about 1 hour')
      end
    end

    context 'with an expired certificate' do
      let(:not_after) { Time.now - 3600 }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('critical')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate has expired about 1 hour ago')
      end
    end

    context 'with a non-matching certificate' do
      let(:certificate_hostname) { 'example.net' }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('critical')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('certificate subject does not match hostname')
      end
    end
    context 'without certificate' do
      let(:certificate) { nil }

      it 'state is correct' do
        expect(subject.to_e[:state]).to eq('critical')
      end

      it 'description is correct' do
        expect(subject.to_e[:description]).to eq('example.com does not have a valid certificate')
      end
    end
  end

  context '#certificate' do
    subject do
      CertificateCheckerFactory.new.certificate_checkers_for(specification).first
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
      let(:specification) { 'mx.opus-labs.fr' }

      it 'fetches a certificate' do
        expect(subject.send(:certificate)).to be_a(OpenSSL::X509::Certificate)
      end
    end
  end
end
