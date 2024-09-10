# gRPC C++ Certificate Example

The C++ Certificate example shows how certificate verification might be used to control communication to the server or client. Note that the C++ Certificate API is still experimental and subject to change.

## Certificate generation

Certificates need to be generated according to the address used, in the example the address is localhost and the certificates were generated using:

Step 1: Create a Certificate Authority (CA) aka root certificate

Generate the CA Private Key:
```
$ openssl genpkey -algorithm RSA -out ca.key
```
Generate the CA Certificate:
```
$ openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=MyCA"
```

Step 2: Create a Server Certificate

Generate the Server Private Key:
```
$ openssl genpkey -algorithm RSA -out server.key
```
Generate a Certificate Signing Request (CSR) for the Server:
```
$ openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
```
Generate the Server Certificate Signed by the CA:
```
$ openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256
```

[Optional] Step 4: Verify the Server Certificate:
```
$ openssl verify -CAfile ca.crt server.crt
```

Note: The example shows a very naive CertificateVerifier added to the server and client. It checks if the peer certificate is empty and approves communication if that is not the case.

## Running the example

To run the server -

```
$ tools/bazel run examples/cpp/certificate_verifier:verifier_server
```

To run the client (on a different terminal) -

```
$ tools/bazel run examples/cpp/certificate_verifier:verifier_client
```
