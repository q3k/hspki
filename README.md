HSCloud PKI
===========

a.k.a. API tokens are so 2012

Introduction
------------

The HSCloud Public Key Infrastructure system is a lightweight specification on how microservices within the HSCloud ecosystem authenticate themselves.

The driving force behind this being standardized is to make it very easy for developers to write new microservices and other tools that can mutually authenticate themselves without having to use public TLS certificates, API tokens or passwords.

Each microservice or tool has a key/certificate pair that it uses to both serve incoming requests and to use as a client certificate when performing outgoing requests.

We currently support gRPC as a first-class transport. Other transports (HTTPS for debug pages, HTTPS for JSON(-RPC)) are not yet implemented.

Where do I get certificates from?
---------------------------------

The distribution of HSPKI certificates to production services is currently being designed (and will likely be based on Hashicorp Vault or a similar NIH tool). For development purposes, the `gen.sh` script in `dev-certs/` can be used to generate a temporary CA, service keypair and developer keypair.

Concepts
--------

All certs for mutual auth have the following CN/SAN format:

   <job>.<principal>.<realm>

For example, if principal maps into a 'group' and job into a 'user':

   arista-proxy-dcr01u23.cluster-management-prod.c.example.com

   job = arista-proxy-dcr01u23
   principal = cluster-management-prod
   realm = c.example.com

The Realm is a DNS name that is global to all jobs that need mutual authentication.

The Principal is any name that carries significance for logical grouping of jobs.
It can, but doesn't need to, group jobs by similar permissions.

The Job is any name that identifies uniquely (within the principal) a security
endpoint that describes a single security policy for a gRPC endpoint.

The entire CN should be DNS resolvable into an IP address that would respond to
gRPC requests on port 42000 (with a server TLS certificate that represents this CN) if the
job represents a service.

This maps nicely to the Kubernetes Cluster DNS format if you set `realm` to `svc.cluster.local`.
Then, `principal` maps to a Kubernetes namespace, and `job` maps into a Kubernetes service.

    arista-proxy-dcr01u23.infrastructure-prod.svc.cluster.local

    job/service = arista-proxy-dcr01u23
    principal/namespace = infrastructure-prod
    realm = svc.cluster.local

ACL, or How do I restrict access to my service?
-----------------------------------------------

Currently you'll have to manually check the PKI information via your language's library and reject unauthorized access within your handler. A unified ACL system with an external RBAC store is currently being designed.

Go Library
==========

We provide a Go library that all microservices should use to interact with HSPKI.

Usage with gRPC
---------------

In lieu of a godoc (soon (TM)), here's a quick usage example:


    import (
        "code.hackerspace.pl/q3k/hspki"
    )
    ...
    g := grpc.NewServer(hspki.WithServerHSPKI()...)
    pb.RegiserXXXServer(g, service)
    ...

Flags
-----

Once linked into your program, the following flags will be automatically present:

    -hspki_realm string
        PKI realm (default "svc.cluster.local")
    -hspki_tls_ca_path string
        Path to PKI CA certificate (default "pki/ca.pem")
    -hspki_tls_certificate_path string
        Path to PKI service certificate (default "pki/service.pem")
    -hspki_tls_key_path string
        Path to PKI service private key (default "pki/service-key.pem")

These should be set accordingly in your development environment.
