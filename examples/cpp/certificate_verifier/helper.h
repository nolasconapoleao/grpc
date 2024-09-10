#pragma once

#include <memory>

#include <grpcpp/grpcpp.h>

using grpc::experimental::ExternalCertificateVerifier;
using grpc::experimental::TlsCustomVerificationCheckRequest;

std::shared_ptr<grpc::ChannelCredentials> CreateTlsChannelCredentials(
  std::string ca_cert,
  std::string server_cert,
  std::string server_key);

std::shared_ptr<grpc::ServerCredentials> CreateTlsServerCredentials(
  std::string root_cert,
  std::string server_cert,
  std::string server_key);

class TestCertificateVerifier
    : public ExternalCertificateVerifier {
  public:
    explicit TestCertificateVerifier(bool success) : success_(success) {}
    ~TestCertificateVerifier() override {}

    bool Verify(TlsCustomVerificationCheckRequest* request,
      std::function<void(grpc::Status)> callback,
      grpc::Status* sync_status) override;
    void Cancel(TlsCustomVerificationCheckRequest* request) override {
    }
  private:
    bool success_ = false;
};
