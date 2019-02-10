# frozen_string_literal: true

RSpec.describe CertificateCheckerFactory do
  describe '#certificate_checkers_for' do
    let(:hostname) { 'example.com' }
    let(:specification) { hostname }

    before do
      expect(subject.instance_variable_get('@resolver')).to receive(:getaddresses).with(hostname).and_return([:ip])
    end

    context 'with a random hostname' do
      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('example.com', :ip, 443, :raw).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(443)
        expect(result[0].starttls).to eq(:raw)
      end
    end

    context 'with a SMTP hostname' do
      let(:hostname) { 'smtp.example.com' }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('smtp.example.com', :ip, 25, :smtp).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(25)
        expect(result[0].starttls).to eq(:smtp)
      end
    end

    context 'with an IMAP hostname' do
      let(:hostname) { 'imap.example.com' }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('imap.example.com', :ip, 143, :imap).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(143)
        expect(result[0].starttls).to eq(:imap)
      end
    end

    context 'with a LDAP hostname' do
      let(:hostname) { 'ldap.example.com' }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('ldap.example.com', :ip, 389, :ldap).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(389)
        expect(result[0].starttls).to eq(:ldap)
      end
    end

    context 'with a Puppet hostname' do
      let(:hostname) { 'puppet.example.com' }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('puppet.example.com', :ip, 8140, :raw).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(8140)
        expect(result[0].starttls).to eq(:raw)
      end
    end

    context 'with a hostname and a port' do
      let(:specification) { "#{hostname}:25" }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('example.com', :ip, 25, :smtp).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(25)
        expect(result[0].starttls).to eq(:smtp)
      end
    end

    context 'with a hostname, a port and starttls settings' do
      let(:specification) { "#{hostname}:224:smtp" }

      it 'has proper port and starttls' do
        expect(CertificateChecker).to receive(:new).with('example.com', :ip, 224, :smtp).and_call_original

        result = subject.certificate_checkers_for(specification)

        expect(result.size).to eq(1)
        expect(result[0].port).to eq(224)
        expect(result[0].starttls).to eq(:smtp)
      end
    end
  end
end
