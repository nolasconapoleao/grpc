/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include <grpcpp/grpcpp.h>

#include "helper.h"
#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

#include <iostream>
#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

using grpc::experimental::ExternalCertificateVerifier;
using grpc::experimental::TlsCustomVerificationCheckRequest;

ABSL_FLAG(std::string, target, "localhost:50051", "Server address");

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using grpc::experimental::StaticDataCertificateProvider;
using grpc::experimental::IdentityKeyCertPair;

class GreeterClient {
 public:
  GreeterClient(std::shared_ptr<Channel> channel)
      : stub_(Greeter::NewStub(channel)) {}

  // Assembles the client's payload, sends it and presents the response back
  // from the server.
  std::string SayHello(const std::string& user) {
    // Data we are sending to the server.
    HelloRequest request;
    request.set_name(user);

    // Container for the data we expect from the server.
    HelloReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->SayHello(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return "RPC failed";
    }
  }

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

std::string ca_cert = R"(-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUEgsv2XdOGiDu0s8OmDVT6vpvjk4wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwETXlDQTAeFw0yNDA5MDkxNTE4MjJaFw0yNTA5MDkxNTE4
MjJaMA8xDTALBgNVBAMMBE15Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC0hoNdKMfmZkp3RouARUsxED0Bu4OaOjZftvvoVdqMoMqJsJEyi4zAR+ho
0bs/0yGw4MQfQyXVtv/+P/0r+pSPFQeNweyPqzFKe0eMaBL2DNxWHNbAUCvivUI7
2oGOul1M7rupI2bEKRUEnq8oAjV8f1HVwWY6huBH4FLTdsggsnc1WWqjZceNDGVz
Qq3lo27apMAhfeLlVqgGXV1Z23u3vQ5/8xYnT/Gk/bvRfEr2LrFx7WFsBk7ajgQy
QXbmkHh0GVDbCAZCuJIk3YzbqTDiUwXdcFaDFcjsHoCojONq+IroR/sFs7/LHtjr
/IwkyO3sacXpMPX5I+mQPBXeTZihAgMBAAGjUzBRMB0GA1UdDgQWBBQzOqHNiqo2
euaxWILuUIj52NW2ujAfBgNVHSMEGDAWgBQzOqHNiqo2euaxWILuUIj52NW2ujAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAsGVCbMe7ClQCtYZFE
lakrC3rv8ue7ip6zNdXk2cyCTK5aEEqt/dP2EINyB4RWbXZLfpHC/oU4qW82jfrf
QCFqeIQj94gFTR2JDVMbYrYyJiUVsdcWnUvLWA3CLdRFquG96tmfPrAzVdhV0Utj
g0phovVcc5pyqeDwS1CqM5RncEFS+fHfvqvaf3EoSbKTdbngxLcXUYQEywo+KVlg
C8j5bTwasraqPXZjl5EAYXBhXx6J0t33UiJrS0XamJEOPOTGcAFaGKb95pbHBCX1
BeXo1uFx7Vtk8Xo56QhjkkOXFBJePZqzuK649icHWN+QKPOMO8469LNjWksn/Xrz
gHnL
-----END CERTIFICATE-----
)";

std::string server_cert = R"(-----BEGIN CERTIFICATE-----
MIICqjCCAZICFBXSuBVnXcJLFDq8kx64p4WjETeKMA0GCSqGSIb3DQEBCwUAMA8x
DTALBgNVBAMMBE15Q0EwHhcNMjQwOTA5MTUxOTE4WhcNMjUwOTA5MTUxOTE4WjAU
MRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC6TtLbYnCuQa5SKOreDamYzE/Ka5mVoOFoh0T+hlGMIjjw+aB+TfnCa/3u
xbhkH7bXPBGmFTm92lPOMSOBJxaOx5cEaRdYoPTTZchBT8BRndB6dymj3U7mpwwS
WwOieHalv/WXm5TzodI+utTVIkmcvgL5WQuAQvVVSsqgwfxMf3F4CKutocsYlDhG
HcxQY/pUr4rGU21bhU9VH+h0uujuJmnLPKkILvbRX3cTcu3psLNvrcjdVBzHLEq4
gcMwxNAU7HQM1/7t/0s0w86g1D6aWYdPxwJ4R9cnWZ2e/u3J4e2mpSfDtkRtQ/PY
eW0F+bHGEl/UG2IHOud0EJFTQoG7AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAGHd
R4eWG51mW/DAOa7m5+IIVgS2NhAXfsOotfwQeX2dY49Hkgaf63q1f1lfHc1HUjkR
Vg+8ypxUohtqzEM1RYDAHGFoiDFEdCNFvGqiCusS7Ql1OwAkECH3oU8P/2u+wgju
hdpnTiQvvUKObmTIJVYzzpuNmHWx758lD2X69aXH5bV2eTnhPlxsK+ct5YfgtUSJ
guJkvtbtxzeuoiUL3frYztyZN0xUw1j7FeTxyLJxYVPqluGUqkRKyLqcg8v5JTt8
YxatRU+lvptxLAOvBeLyCsr6fXwsMPH5UMNeH5mBEIg9Vec1XiyS8XmX/eTE2n+p
shiBdkDyfSTUBKPPjcc=
-----END CERTIFICATE-----
)";

std::string server_key = R"(-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6TtLbYnCuQa5S
KOreDamYzE/Ka5mVoOFoh0T+hlGMIjjw+aB+TfnCa/3uxbhkH7bXPBGmFTm92lPO
MSOBJxaOx5cEaRdYoPTTZchBT8BRndB6dymj3U7mpwwSWwOieHalv/WXm5TzodI+
utTVIkmcvgL5WQuAQvVVSsqgwfxMf3F4CKutocsYlDhGHcxQY/pUr4rGU21bhU9V
H+h0uujuJmnLPKkILvbRX3cTcu3psLNvrcjdVBzHLEq4gcMwxNAU7HQM1/7t/0s0
w86g1D6aWYdPxwJ4R9cnWZ2e/u3J4e2mpSfDtkRtQ/PYeW0F+bHGEl/UG2IHOud0
EJFTQoG7AgMBAAECggEABhLOajsfTM70qg84v/jWfhYD4hlppv28hhJ7tNzeweed
ec9bOdER0RKBgZMqRlXAjs88RdRvwI5wmkpkPXdhL/yZsCgCNtOobqSsHMa4yWIe
w/SaEgQgBQI4ovepCOUVUfnxWd2qwy9a2QUbgxVqnj8/78rFG+DaCFnFmUHH3nEn
MXXfixKY6oE11DErZXVGNGxwy6ygfMn5/nBI9EjkAtl649rqpqeGL6xP5vQwqumr
ZjLrrxjv+9yIBiW0FHZrW7i4dPF6tYwtA+X80KeJGPheIfUlw3dxD+FFJqhKRVuS
Mqh15aXJEliqzVu3Ap54EnJkALIAvpbSRpABEcv5IQKBgQD7/q4UqJ3FgAkF7I3n
N1gro4oQzqFdIM1LHTjAsM4N746gpNmNvFYD68qOLYSiWiQ7aOrEA2XBb+jDULRU
UDUqZ3vJDaVvrQ/baWSLYxUoJ8C0Iu6yA++DCsmKM38Jir4Pp5MkO5EWD3gN54iD
pRpb1YHL8imsh9gO16BsfrqLJQKBgQC9ROAx07XzTbsj2yWKFqz/20YwaF+183ys
/TVaqamBPJBIATYSUiMjxnKBFZVnTtRMzG9lG9ckEoCS2qCyoAkJztJsiqe138VS
68O5T91XChfyeibmWU53V3NM/3vyKXUVAjaj85mXei+4sosYjK8wjQ3qDaPIfgAP
THDu/GazXwKBgHUBdhcFi+xOXOIxSlpXqkro7oyLRQWW23vLH7To42Q5HUKeCJ31
GwNLEowdun4f2L71IjzNTwwYSD2YVYLokycTUbiy62QFOV2pfBP0d7hjbOi3Z5mk
liuEcLwI2S23DDT8nCewuNdDa30ZSpvFp42If3IRCSShFsMdf9GgrkE5AoGAAg/g
CWrvDomIQmm+zPRWSitPZnOcp1TRxOi1ThmPGTNZtw8cUbLHYzpkQPfFOuzm7zdC
920IOQJimDb9jTSlJJA2Rqx0C002zyJ2bWxrUulvPVsLVXMfobk4LlySMx80gVgW
1E5xG+9e2bpIPao6tmKzBhvD7wlAYupISLJDRC0CgYBgzyDOjf23s7XFnw51V72k
yzI5DW7YMrVoujQyk+S00wTmlEa2NARAJj7rPDZpGPW6VM0/n18fnT2raF+LHxeZ
O1+smifQPAzrRbj7R/hwdZuLyyQPiRqGZHaOfnBBaCxvklnBUsupujH0vTy0N1TO
gQpkG/wCNnIGHr6jcq3rKg==
-----END PRIVATE KEY-----
)";

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  std::string target_str = absl::GetFlag(FLAGS_target);

  const auto channel_credentials = CreateTlsChannelCredentials(ca_cert, server_cert, server_key); 
  GreeterClient greeter(grpc::CreateChannel(target_str, channel_credentials));
  std::string user("world");
  std::string reply = greeter.SayHello(user);
  std::cout << "Greeter received: " << reply << std::endl;

  return 0;
}
