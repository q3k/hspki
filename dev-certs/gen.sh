#!/bin/sh

set -e -x

test -f ca.pem || ( cfssl gencert -initca ca_csr.json | cfssljson -bare ca )
test -f service.pem || ( cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca_config.json -profile=test service_csr.json | cfssljson -bare service )
test -f client.pem || ( cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca_config.json -profile=test client_csr.json | cfssljson -bare client )
