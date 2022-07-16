# frozen_string_literal: true

RSpec.describe TLSChecker::CertificateCheckerFactory do
  let(:factory) { described_class.new }

  before do
    # rubocop:disable RSpec/AnyInstance
    allow_any_instance_of(TLSChecker::CertificateChecker).to receive(:check).and_return(true)
    allow_any_instance_of(TLSChecker::TLSACheckerFactory).to receive(:tlsa_checkers_for).and_return([])
    # rubocop:enable RSpec/AnyInstance
  end

  describe '#certificate_checkers_for' do
    subject { result }

    let(:hostname) { 'example.com' }
    let(:specification) { hostname }
    let(:result) { factory.certificate_checkers_for(specification) }
    let(:resolver) { factory.instance_variable_get('@resolver') }

    before do
      allow(resolver).to receive(:getaddresses).with(hostname).and_return([:ip])
    end

    context 'with a random hostname' do
      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('example.com', :ip, 443, :raw).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('example.com', :ip, 443, :raw)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 443) }
        it { is_expected.to have_attributes(starttls: :raw) }
      end
    end

    context 'with a SMTP hostname' do
      let(:hostname) { 'smtp.example.com' }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('smtp.example.com', :ip, 25, :smtp).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('smtp.example.com', :ip, 25, :smtp)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 25) }
        it { is_expected.to have_attributes(starttls: :smtp) }
      end
    end

    context 'with an IMAP hostname' do
      let(:hostname) { 'imap.example.com' }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('imap.example.com', :ip, 143, :imap).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('imap.example.com', :ip, 143, :imap)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 143) }
        it { is_expected.to have_attributes(starttls: :imap) }
      end
    end

    context 'with a LDAP hostname' do
      let(:hostname) { 'ldap.example.com' }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('ldap.example.com', :ip, 389, :ldap).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('ldap.example.com', :ip, 389, :ldap)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 389) }
        it { is_expected.to have_attributes(starttls: :ldap) }
      end
    end

    context 'with a Puppet hostname' do
      let(:hostname) { 'puppet.example.com' }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('puppet.example.com', :ip, 8140, :raw).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('puppet.example.com', :ip, 8140, :raw)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 8140) }
        it { is_expected.to have_attributes(starttls: :raw) }
      end
    end

    context 'with a hostname and a port' do
      let(:specification) { "#{hostname}:25" }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('example.com', :ip, 25, :smtp).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('example.com', :ip, 25, :smtp)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 25) }
        it { is_expected.to have_attributes(starttls: :smtp) }
      end
    end

    context 'with a hostname, a port and starttls settings' do
      let(:specification) { "#{hostname}:224:smtp" }

      before do
        allow(TLSChecker::CertificateChecker).to receive(:new).with('example.com', :ip, 224, :smtp).and_call_original
      end

      it do
        result
        expect(TLSChecker::CertificateChecker).to have_received(:new).with('example.com', :ip, 224, :smtp)
      end

      it { is_expected.to be_an(Array) }
      it { is_expected.to have_attributes(size: 1) }

      describe 'first item' do
        subject { result[0] }

        it { is_expected.to have_attributes(port: 224) }
        it { is_expected.to have_attributes(starttls: :smtp) }
      end
    end
  end
end
