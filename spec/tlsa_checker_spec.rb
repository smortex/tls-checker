# frozen_string_literal: true

RSpec.describe TLSChecker::TLSAChecker do
  subject do
    TLSChecker::TLSAChecker.new(record, certificate_checker)
  end

  let(:record) do
    Resolv::DNS::Resource::IN::TLSA.new("\x03\x00\x01\x01\x5a\xd9\xa7\xcb\x61\x43\x17\x33\xb4\x83\xcd\x7e\x15\x5f\x38" \
                                        "\xf7\xa7\x76\xfa\x0e\xf7\xf0\xed\x94\xda\x3c\xa8\xd8\x6c\x21\x0a")
  end

  let(:certificate_checker) do
    checker = TLSChecker::CertificateChecker.new('mx.blogreen.org', Resolv::IPv6.create('2001:DB8::25'), 25, :smtp)
    checker.instance_variable_set(:@certificate, OpenSSL::X509::Certificate.new(File.read('spec/mx.blogreen.org.crt')))
    checker
  end

  it 'reports a correct state' do
    expect(subject.to_e[:state]).to eq('ok')
  end

  it 'reports a correct service' do
    expect(subject.to_e[:service]).to eq('X.509/mx.blogreen.org/[2001:DB8::25]:25/TLSA')
  end
end
