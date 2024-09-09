#include "ab_certificate_verifier.h"

using grpc::experimental::TlsCustomVerificationCheckRequest;

bool ABCertificateVerifier::Verify(TlsCustomVerificationCheckRequest* request,
  std::function<void(grpc::Status)> callback,
  grpc::Status* sync_status) {
    if (!success_) {
      *sync_status = grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                  "SyncCertificateVerifier failed");
    } else {
      *sync_status = grpc::Status(grpc::StatusCode::OK, "");
    }

    if(request->peer_cert().empty()) {
      std::cout << "Empty certificate" << std::endl;
      return false;
    }

    // check environment variable, if not set, return false
    const char* env_var = std::getenv("SERVER");
    if(env_var == nullptr) {
      std::cout << "SERVER is not set" << std::endl;
      return false;
    }
    return true;
};
