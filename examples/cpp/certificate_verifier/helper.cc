#include "helper.h"

#include <iostream>
#include <string>

#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>

using grpc::experimental::TlsServerCredentials;
using grpc::experimental::TlsServerCredentialsOptions;
using grpc::experimental::StaticDataCertificateProvider;
using grpc::experimental::IdentityKeyCertPair;
using grpc::experimental::TlsCustomVerificationCheckRequest;

std::shared_ptr<grpc::ChannelCredentials> CreateTlsChannelCredentials(
    std::string ca_cert,
    std::string server_cert,
    std::string server_key) {
  std::vector<IdentityKeyCertPair> identity_pair;
  identity_pair.emplace_back(IdentityKeyCertPair{server_key, server_cert});

  auto certificate_provider = std::make_shared<StaticDataCertificateProvider>(ca_cert, identity_pair);
  grpc::experimental::TlsChannelCredentialsOptions options;
  options.set_certificate_provider(std::move(certificate_provider));
  options.watch_root_certs();
  options.watch_identity_key_cert_pairs();
  auto verifier = ExternalCertificateVerifier::Create<TestCertificateVerifier>(true);
  options.set_certificate_verifier(std::move(verifier));
  options.set_verify_server_certs(true);
  options.set_check_call_host(false);
  return grpc::experimental::TlsCredentials(options);
}

std::shared_ptr<grpc::ServerCredentials> CreateTlsServerCredentials(
    std::string root_cert,
    std::string server_cert,
    std::string server_key) {
  std::vector<IdentityKeyCertPair> identity_key_cert_pairs;
  identity_key_cert_pairs.emplace_back(IdentityKeyCertPair{server_key, server_cert});
  auto certificate_provider = std::make_shared<StaticDataCertificateProvider>(root_cert, identity_key_cert_pairs);
  TlsServerCredentialsOptions options(certificate_provider);
  options.set_certificate_provider(std::move(certificate_provider));

  auto verifier = ExternalCertificateVerifier::Create<TestCertificateVerifier>(true);
  options.set_certificate_verifier(std::move(verifier));
  
  options.watch_root_certs();
  options.set_root_cert_name("root");
  options.watch_identity_key_cert_pairs();
  options.set_identity_cert_name("identity");
  options.set_cert_request_type(
      GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  return TlsServerCredentials(options);
}

bool TestCertificateVerifier::Verify(TlsCustomVerificationCheckRequest* request,
  std::function<void(grpc::Status)> callback,
  grpc::Status* sync_status) {
    if (!success_) {
      *sync_status = grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                  "SyncCertificateVerifier failed");
    } else {
      *sync_status = grpc::Status(grpc::StatusCode::OK, "");
    }

    // Add custom verification here
    if(request->peer_cert().empty()) {
      std::cout << "Empty certificate" << std::endl;
      return false;
    }

    return true;
};
