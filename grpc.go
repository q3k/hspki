package hspki

// Copyright 2018 Sergiusz Bazanski <q3k@hackerspace.pl>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	log "github.com/inconshreveable/log15"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	flagCAPath          string
	flagCertificatePath string
	flagKeyPath         string
	flagPKIRealm        string

	// Enable logging HSPKI info into traces
	Trace = true
	Log   = log.New()
)

const (
	ctxKeyClientInfo = "hspki-client-info"
)

func init() {
	flag.StringVar(&flagCAPath, "hspki_tls_ca_path", "pki/ca.pem", "Path to PKI CA certificate")
	flag.StringVar(&flagCertificatePath, "hspki_tls_certificate_path", "pki/service.pem", "Path to PKI service certificate")
	flag.StringVar(&flagKeyPath, "hspki_tls_key_path", "pki/service-key.pem", "Path to PKI service private key")
	flag.StringVar(&flagPKIRealm, "hspki_realm", "svc.cluster.local", "PKI realm")
	Log.SetHandler(log.DiscardHandler())
}

func maybeTrace(ctx context.Context, f string, args ...interface{}) {
	fmtd := fmt.Sprintf(f, args...)
	Log.Info("trace msg", fmtd)

	if !Trace {
		return
	}

	tr, ok := trace.FromContext(ctx)
	if !ok {
		log.Warn("no trace", "msg", fmtd)
		return
	}
	tr.LazyPrintf(f, args...)
}

func parseClientName(name string) (*ClientInfo, error) {
	if !strings.HasSuffix(name, "."+flagPKIRealm) {
		return nil, fmt.Errorf("invalid realm")
	}
	service := strings.TrimSuffix(name, "."+flagPKIRealm)
	parts := strings.Split(service, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid job/principal format")
	}
	return &ClientInfo{
		Realm:     flagPKIRealm,
		Principal: parts[1],
		Job:       parts[0],
	}, nil
}

func withPKIInfo(ctx context.Context, c *ClientInfo) context.Context {
	maybeTrace(ctx, "HSPKI: Applying ClientInfo: %s", c.String())
	return context.WithValue(ctx, ctxKeyClientInfo, c)
}

func grpcInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		maybeTrace(ctx, "HSPKI: Could not establish identity of peer.")
		return nil, status.Errorf(codes.PermissionDenied, "no peer info")
	}

	authInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		maybeTrace(ctx, "HSPKI: Could not establish TLS identity of peer.")
		return nil, status.Errorf(codes.PermissionDenied, "no TLS certificate presented")
	}

	chains := authInfo.State.VerifiedChains
	if len(chains) != 1 {
		maybeTrace(ctx, "HSPKI: No trusted chains found.")
		return nil, status.Errorf(codes.PermissionDenied, "no trusted TLS certificate presented")
	}

	chain := chains[0]

	certDNs := make([]string, len(chain))
	for i, cert := range chain {
		certDNs[i] = cert.Subject.String()
	}
	maybeTrace(ctx, "HSPKI: Trust chain: %s", strings.Join(certDNs, ", "))

	clientInfo, err := parseClientName(chain[0].Subject.CommonName)
	if err != nil {
		maybeTrace(ctx, "HSPKI: Invalid CN %q: %v", chain[0].Subject.CommonName, err)
		return nil, status.Errorf(codes.PermissionDenied, "invalid TLS CN format")
	}
	ctx = withPKIInfo(ctx, clientInfo)
	return handler(ctx, req)
}

// ClientInfo contains information about the HSPKI authentication data of the
// gRPC client that has made the request.
type ClientInfo struct {
	Realm     string
	Principal string
	Job       string
}

// String returns a human-readable representation of the ClientInfo in the
// form "job=foo, principal=bar, realm=baz".
func (c *ClientInfo) String() string {
	return fmt.Sprintf("job=%q, principal=%q, realm=%q", c.Job, c.Principal, c.Realm)
}

// ClientInfoFromContext returns ClientInfo from a gRPC service context.
func ClientInfoFromContext(ctx context.Context) *ClientInfo {
	v := ctx.Value(ctxKeyClientInfo)
	if v == nil {
		return nil
	}
	ci, ok := v.(*ClientInfo)
	if !ok {
		return nil
	}
	return ci
}

// WithServerHSPKI is a grpc.ServerOptions array that ensures that the gRPC server:
// - runs with HSPKI TLS Service Certificate
// - rejects all non_HSPKI compatible requests
// - injects ClientInfo into the service context, which can be later retrieved
//   using ClientInfoFromContext
func WithServerHSPKI() []grpc.ServerOption {
	if !flag.Parsed() {
		log.Crit("WithServerHSPKI called before flag.Parse!")
	}
	serverCert, err := tls.LoadX509KeyPair(flagCertificatePath, flagKeyPath)
	if err != nil {
		log.Crit("WithServerHSPKI: cannot load service certificate/key", "err", err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(flagCAPath)
	if err != nil {
		log.Crit("WithServerHSPKI: cannot load CA certificate", "err", err)
	}
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Crit("WithServerHSPKI: cannot use CA certificate", "err", err)
	}

	creds := grpc.Creds(credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    certPool,
	}))

	interceptor := grpc.UnaryInterceptor(grpcInterceptor)

	return []grpc.ServerOption{creds, interceptor}
}
