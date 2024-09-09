#pragma once

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>

using grpc::experimental::ExternalCertificateVerifier;
using grpc::experimental::TlsCustomVerificationCheckRequest;

class ABCertificateVerifier
    : public ExternalCertificateVerifier {
  public:
    explicit ABCertificateVerifier(bool success) : success_(success) {}
    ~ABCertificateVerifier() override {}

    bool Verify(TlsCustomVerificationCheckRequest* request,
      std::function<void(grpc::Status)> callback,
      grpc::Status* sync_status) override;
    void Cancel(TlsCustomVerificationCheckRequest* request) override {
    }
  private:
    bool success_ = false;
};
