---
title: "Secure Negotiation of Incompatible Protocols in TLS"
abbrev: "Authenticating Incompatible Protocols"
docname: draft-thomson-tls-snip-latest
category: info
ipr: trust200902

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
 -
    ins: M.  Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net


--- abstract

An extension is defined for TLS that allows a client and server to detect an
attempt to force the use of less-preferred application protocol even where
protocol options are incompatible.  This supplements application-layer protocol
negotiation, which allows choices between compatible protocols to be
authenticated.


--- middle

# Introduction

With increased diversity in protocol choice, some applications are able to use
one of several semantically-equivalent protocols to achieve their goals.  This
is particularly notable in HTTP where there are currently three distinct
protocols: HTTP/1.1 {{?HTTP11=I-D.ietf-httpbis-messaging}}, HTTP/2
{{?HTTP2=RFC7540}}, and HTTP/3 {{?HTTP3=I-D.ietf-quic-http}}.  This is also true
for protocols that support variants based on both TLS {{?TLS=RFC8446}} and DTLS
{{?DTLS=I-D.ietf-tls-dtls13}}.

For protocols that are mutually compatible, Application-Layer Protocol
Negotiation (ALPN; {{?ALPN=RFC7301}}) provides a secure way to negotiate
protocol selection.

In ALPN, the client offers a list of options in a TLS ClientHello and the server
chooses the option that it most prefers.  A downgrade attack occurs where both
client and server support a protocol that the server prefers more than than the
selected protocol.  ALPN protects against this attack by ensuring that the
server is aware of all options the client supports and including those options
and the server choice under the integrity protection provided by the TLS
handshake.

This downgrade protection functions because protocol negotiation is part of the
TLS handshake.  The introduction of semantically-equivalent protocols that use
incompatible handshakes introduces new opportunities for downgrade attack.  For
instance, it is not possible to negotiate the use of HTTP/2 based on an attempt
to connect using HTTP/3.  The former relies on TCP, whereas the latter uses UDP.
These protocols are therefore mutually incompatible.

This document defines an extension to TLS that allows clients to discover when
servers support alternative protocols that are incompatible with the
currently-selected TLS version.  This might be used to avoid downgrade attack
caused by interference in protocol discovery mechanisms.

This extension is motivated by the addition of new mechanisms, such as
{{?SVCB=I-D.ietf-dnsop-svcb-httpssvc}}.  SVCB enables the discovery of servers
that support multiple different protocols, some of which are incompatible.  The
extension can also be used to authenticate protocol choices that are discovered
by other means.


# Terminology

{::boilerplate bcp14}

Two protocols are consider "compatible" if it is possible to negotiate either
using the same connection attempt.  In comparison, protocols are "incompatible"
if they require separate attempts to establish a connection.


# Incompatible Protocols and SVCB

The SVCB record {{?SVCB}} allows a client to learn about services associated
with a domain name.  This includes how to locate a server, along with
supplementary information about the server, including protocols that the server
supports.  This allows a client to start using a protocol of their choice
without added latency, as the lookup can be performed concurrently with other
name resolution.  The added cost of the additional DNS queries is minimal.

However, SVCB provides no protection against a downgrade attack between
incompatible protocols.  An attacker could remove DNS records for
client-preferred protocols, leaving the client to believe that only
less-prefered, mutually-incompatible options are available.  The client only
offers compatible options to a server in its TLS handshake.  Even if a client
were to inform the server that it supports a more preferred protocol, the server
would not be able to act upon it.

Authenticating all of the information presented in SVCB records might provide
clients with complete information about server support, but this is impractical
for several reasons:

* it is not possible to ensure that all server instances in a deployment have
  the same protocol configuration, as deployments for a single name routinely
  include multiple providers that cannot coordinate closely;

* the ability to provide a subset of valid DNS records is integral to many
  strategies for managing servers; and

* it is difficult to ensure that cached DNS records are synchronized with server
  state.

Overall, an authenticated TLS handshake is a better source of authoritative
information about the protocols that are supported.


# Authenticating Incompatible Protocols

The incompatible_protocols(TBD) TLS extension provides clients with information about
the incompatible protocols that are supported by servers.

~~~tls-syntax
enum {
    incompatible_protocols(TBD), (65535)
} ExtensionType;
~~~

A client that supports the extension advertises an empty extension.  In
response, a server that supports this extension includes a list of application
protocol identifiers.  The "extension_data" field of the value server extension
uses the `ProtocolNameList` format defined in {{!ALPN}}.  This syntax is shown
in {{fig-syntax}}.

~~~tls-syntax
struct {
  select (Handshake.msg_type) {
    case client_hello:
      Empty;
    case encrypted_extensions:
      ProtocolNameList incompatible_protocols;
  };
} IncompatibleProtocols;
~~~
{: #fig-syntax title="TLS Syntax for incompatible_protocols Extension"}

This extension only applies to the ClientHello and EncryptedExtensions messages.
An implementation that receives this extension in any other handshake message
MUST send a fatal illegal_parameter alert.

A server deployment that supports multiple incompatible protocols MAY advertise
all protocols that are supported.  A server MAY limit this to protocols that it
considers to have similar semantics to protocols that the client lists in its
application_layer_protocol_negotiation extension.

The definition of what a server includes is intentionally loose.  It is better
that a server offer more information than less as the needs of a client are not
necessarily well reflected in its ALPN extension.  However, it is not reasonable
to require that a server advertise all potential protocols as that is unlikely
to be practical.

A server MUST omit any compatible protocols from this extension on the
understanding that the client will include compatible protocols in the
application_layer_protocol_negotiation extension.

A server needs to ensure that protocols advertised in this fashion are available
to the client within the same protocol authentication scope.


# Protocol Authentication Scope

The protocol authentication scope is the set of protocol endpoints at a server
that share a protocol configuration.  A client learns of this scope as part of
the process it follows to discover the server.

By default, the protocol authentication scope is a single protocol endpoint.
The default protocol authentication scope offers no means to authenticate
incompatible protocols as it is not possible for a client to access any endpoint
that supports those protocols.  A client cannot use information from the
incompatible_protocols extension unless a wider scope is used.

\[\[TODO: This likely needs some discussion.]]


## SVCB Discovery Scope

For SVCB records, the protocol authentication scope is defined by the set of
ServiceForm SVCB records with the same SvcDomainName.

This ensures that the final choice a client makes between ServiceForm SVCB
records is protected by this extension.  If the client does not receive a SVCB
record for a protocol that the server includes in its incompatible_protocols
extension, then it can assume that this omission was caused by an error or
attack.

Thus, for SVCB, a choice between AliasForm records (or CNAME or DNAME records)
is not authenticated, but choices between ServiceForm records is.  This allows
for server deployments for the same name to have different administrative
control and protocol configurations.


## QUIC Version Negotiation

TODO: define how this can be used to authenticate protocol choices where there
are incompatible QUIC versions.


## Alternative Services

It is possible to negotiate protocols based on an established connection without
exposure to downgrade.  The Alternative Services {{?ALTSVC=RFC7838}}
bootstrapping in HTTP/3 does just that.  Assuming that HTTP/2 or HTTP/1.1 are
not vulnerable to attacks that would compromise integrity, a server can
advertise the presence of an endpoint that supports HTTP/3.

Alternative Services is secure, but it has suboptimal performance.  A client
could attempt the protocol it prefers most, but that comes at a risk that this
protocol is not supported by a server.  A client could implement a fallback,
which might even be performed concurrently (see {{?HAPPY-EYEBALLS=RFC6555}}),
but this costs time and resources.  A client avoids these costs by attempting
the protocol it believes to be most widely supported, though this comes with a
performance penalty in cases where the most-preferred protocol is supported.

A server that is discovered using Alternative Services uses the default protocol
authentication scope.  As use of Alternative Services is discretionary for both
client and server, a client cannot expect to receive information about
incompatible protocols.  To avoid downgrade, a client only has to avoid using an
Alternative Service that offers a less-preferred protocol.


## Scope for Other Discovery Methods

For other discovery methods, a definition for protocol authentication scope is
needed before a client can act on what is learned using the
incompatible_protocols extension.  That definition needs to define how to
discover server instances that support all incompatible protocols in the scope.

In particular, a server that is discovered using forms of DNS-based name
resolution other than SVCB uses the default protocol authentication scope.  This
discovery method does not provide enough information to locate other
incompatible protocols.

For instance, an HTTPS server that is discovered using purely A or AAAA records
(and CNAME or DNAME records) might advertise support for incompatible protocols,
but as there is no way to determine where those protocols are supported, a
client cannot act on the information.  Note that Alternative Services do not
change the protocol authentication scope.

Deployments of discovery methods that define a protocol authentication scope
larger than the default need to ensure that every server provides information
that is consistent with every protocol authentication scope that includes that
server.  A server that fails to indicate support for a protocol that is within
a protocol authentication scope does not offer any protection against attack; a
server that advertises a protocol that the client cannot discover risks this
misconfiguration being identified as an attack by clients.


# Incompatible Protocol Selection

This represents a different model for protocol selection than the one used by
ALPN.  In ALPN, the client presents a set of (compatible) options and the server
chooses its most preferred.

In comparison, as the client makes a selection between incompatible protocols
before making a connection attempt, this design only provides the client with
information about other incompatible protocols that the server might support.
Any choice to attempt a connection using those protocols is left to the client.

In summary:

* For compatible protocols, the server chooses

* For incompatible protocols, the client chooses

Detecting a potential downgrade between incompatible protocols does not
automatically imply that a client abandon a connection attempt.  This is left to
client policy.

For a protocol like HTTP/3, this might not result in the client choosing to use
HTTP/3, even if the server prefers that protocol.  Blocking of UDP or QUIC is
known to be widespread.  As a result, clients might adopt a policy of tolerating
a downgrade to a TCP-based protocol, even if HTTP/3 were preferred.  However, as
blocking of UDP is highly correlated by access network, clients that are able to
establish HTTP/3 connections to some servers might choose to apply a stricter
response when a server that indicates HTTP/3 support is unreachable.


# Security Considerations

This design depends on the integrity of the TLS handshake across all forms,
including TLS {{?RFC8446}}, DTLS {{?DTLS=I-D.ietf-tls-dtls13}}, and QUIC
{{?QUIC-TLS=I-D.ietf-quic-tls}}.  An attacker that can modify a TLS handshake in
any one of these protocols can cause a client to believe that other options do
not exist.

A server deployment that uses AliasForm SVCB records and does not uniformly
support a client-preferred protocol is vulnerable to downgrade attacks that
steer clients toward instances that lack support for that protocol.  This attack
is ineffective for protocols that are consistently supported by all server
instances.


# IANA Considerations

TODO: register the extension


--- back

# Acknowledgments


