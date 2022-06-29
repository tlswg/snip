---
title: "Secure Negotiation of Incompatible Protocols in TLS"
abbrev: "Authenticating Incompatible Protocols"
docname: draft-ietf-tls-snip-latest
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

informative:
  SVCB: I-D.ietf-dnsop-svcb-https


--- abstract

An extension is defined for TLS that allows a client and server to detect an
attempt to force the use of less-preferred application protocol even where
protocol options are incompatible.  This supplements application-layer protocol
negotiation (ALPN), which allows choices between compatible protocols to be
authenticated.


--- middle

# Introduction

With increased diversity in protocol choice, some applications are able to use
one of several semantically-equivalent protocols to achieve their goals.  This
is particularly notable in HTTP where there are currently three distinct
protocols: HTTP/1.1 {{?HTTP11=I-D.ietf-httpbis-messaging}}, HTTP/2
{{?HTTP2=I-D.ietf-httpbis-http2bis}}, and HTTP/3 {{?HTTP3=I-D.ietf-quic-http}}.
This is also true of protocols that support variants based on both TLS
{{?TLS=RFC8446}} and DTLS {{?DTLS=I-D.ietf-tls-dtls13}}.

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

Downgrade protection in ALPN functions because protocol negotiation is part of
the TLS handshake.  The introduction of semantically-equivalent protocols that
use incompatible handshakes introduces new opportunities for downgrade attack.
For instance, it is not possible to negotiate the use of HTTP/2 based on an
attempt to connect using HTTP/3.  The former relies on TCP, whereas the latter
uses UDP.  These protocols are therefore mutually incompatible and ALPN cannot
be used to securely select between the two.

This document defines an extension to TLS that allows clients to discover when a
server supports alternative protocols that are incompatible with the protocol in
use.  This might be used to detect a downgrade attack.

Downgrade protection for incompatible protocols only works for services provided
by the same logical server (see {{ls}}). That is, the protection only applies to
servers that operate from the same IP address and port number from the
perspective of the client.

This extension is motivated by the addition of new protocols such as HTTP/3
{{HTTP3}} that are semantically equivalent, but incompatible with existing
protocols.

These downgrade protections are intended to work for any method that a client
might use to discover that a server supports a particular protocol.  Special
considerations for HTTP Alternative Services {{!ALTSVC}} is included in
{{alt-svc}}.


# Terminology

{::boilerplate bcp14}

Two protocols are considered "compatible" if it is possible to negotiate either
using the same connection attempt.  In comparison, protocols are "incompatible"
if they require separate attempts to establish a connection.


# Incompatible Protocol Selection {#selection}

This document extends the authentication protections provided by TLS to cover
negotiation of incompatible protocols.

This is complementary to ALPN {{?ALPN}}, which only protects the negotiation of
compatible protocols.  In ALPN, the client presents a set of compatible options
and the server chooses its most preferred.

This extension works by having a server offer a list of incompatible protocols
that it supports on the same logical server (see {{ls}}).  How clients use this
information will depend on client policy.


## Client Policy

A client has to choose between incompatible options before making a connection
attempt.  Thefore, this document does not define a negotiation mechanism, it
only provides authenticated information that a client can use.

Importantly, detecting a potential downgrade between incompatible protocols does
not automatically imply that a client abandon a connection attempt.  It only
provides the client with authenticated information that can help with making a
decision.  What a client does with this information is left to client policy.

For a protocol like HTTP/3, this might not result in the client choosing to use
HTTP/3, even if HTTP/3 is preferred and the server indicates that a service
endpoint supporting HTTP/3 is available.  Blocking of UDP or QUIC is known to be
widespread.  As a result, clients might adopt a policy of tolerating a downgrade
to a TCP-based version of HTTP, even if HTTP/3 were preferred.  However, as
blocking of UDP is highly correlated by access network, clients that are able to
establish HTTP/3 connections to some servers might choose to apply a stricter
policy when a server that indicates HTTP/3 support is unreachable.


## Logical Servers {#ls}

This document relies on the notion of a logical server for determining how a
client interprets information about incompatible protocols.

Clients can assume availability of incompatible protocols across the set of
endpoints that share an IP version, IP address, and port number with the TLS
server that provides the incompatible_protocols extension.

This definition includes a port number that is independent of the protocol that
is used.  Any protocol that defines a port number is considered to be
equivalent.  In particular, incompatible protocols can be deployed to TCP, UDP,
SCTP, or DCCP ports as long as the IP address and port number is the same.

This determination is made from the perspective of a client.  This means that
server operators need to be aware of all instances that might answer to the same
IP address and port; see {{operational}}.


# Authenticating Incompatible Protocols {#extension}

The incompatible_protocols(TBD) TLS extension provides clients with information
about the incompatible protocols that are supported by the same logical server;
see {{ls}} for a definition of a logical server.

~~~tls-syntax
enum {
    incompatible_protocols(TBD), (65535)
} ExtensionType;
~~~

A client that supports the extension advertises an empty extension.  In
response, a server that supports this extension includes a list of application
protocol identifiers.  The "extension_data" field of the server extension uses
the `ProtocolName` type defined in {{!ALPN}}.  This syntax is shown in
{{fig-syntax}}.

~~~tls-syntax
opaque ProtocolName<1..2^8-1>;  // From RFC 7301
ProtocolName IncompatibleProtocol;

struct {
  select (Handshake.msg_type) {
    case client_hello:
      Empty;
    case encrypted_extensions:
      IncompatibleProtocol incompatible_protocols<3..2^16-1>;
  };
} IncompatibleProtocols;
~~~
{: #fig-syntax title="TLS Syntax for incompatible_protocols Extension"}

This extension only applies to the ClientHello and EncryptedExtensions messages.
An implementation that receives this extension in any other handshake message
MUST send a fatal illegal_parameter alert.

Clients and servers MUST include the application_layer_protocol_negotiation
extension if they include an incompatible_protocols extension.  An endpoint that
receives an incompatible_protocols extension without an
application_layer_protocol_negotiation extension MUST send a fatal
missing_extension alert.

A client offers an empty extension to indicate that is wishes to receive
information about incompatible protocols supported by the (logical) server.

A server deployment that supports multiple incompatible protocols MAY advertise
all protocols that are supported by the same logical server.  A server needs to
ensure that protocols advertised in this fashion are available to the client.

A server SHOULD omit any compatible protocols from this extension.  That is, any
protocol that the server might be able to select, had the client offered the
protocol in the application_layer_protocol_negotiation extension.  In
comparison, clients are expected to include all compatible protocols in the
application_layer_protocol_negotiation extension.  This recommendation exists
only so that implementations choose a consistent - and smaller - encoding;
clients MUST NOT abort a handshake if the server lists a compatible protocol.

Information presented by the server is only valid at the time it is provided.  A
client can act on that information immediately, but it cannot retain the
information on the expectation that it will be valid later.  A server therefore
only needs to consider providing information that is current for a period that
would allow the client to act, which might amount to a few seconds.


## Validation

If a client has discovered server endpoints for a preferred protocol that point
to the same logical server, receiving an incompatible_protocols extension that
includes that protocol is a strong indication of a potential downgrade attack.

In response to detecting a potential downgrade attack, a client might abandon
the current connection attempt and report an error.

A client might support an incompatible protocol, but chooses not to attempt its
use under normal conditions might choose not to fail if it learns that the
protocol is supported by the server.  This client might instead make a
connection attempt or initiate discovery for that protocol when it learns that
it is available.


## QUIC Version Negotiation {#quic}

QUIC enables the definition of incompatible protocols that share a port.  The
incompatible_protocols extension can be used to authenticate the choice of
application protocols across incompatible QUIC version.  QUIC version
negotiation {{?QUIC-VN=I-D.ietf-quic-version-negotiation}} is used to
authenticate the choice of QUIC version.

As there are two potentially competing sets of preferences at different protocol
layers, clients need to set preferences for QUIC version and application
protocol are consistent.

For example, if application protocol A exclusively uses QUIC version X and
application protocol B exclusively uses QUIC version Y, setting a preference for
both A and Y will result in one or other option not being selected.  This would
result in failure if the client applied a policy that regarded either downgrade
as an error.


## HTTP Alternative Services {#alt-svc}

It is possible to select incompatible protocols based on an established
connection.  The Alternative Services {{!ALTSVC=RFC7838}} bootstrapping in
HTTP/3 {{?HTTP3}} is not vulnerable to downgrade as the signal is exchanged over
an authenticated connection.  A server can advertise the presence of an endpoint
that supports HTTP/3 using an HTTP/2 or HTTP/1.1 connection.

A client can choose to ignore incompatible protocols when attempting to use an
alternative service.


# Operational Considerations {#operational}

By listing incompatible protocols a server needs to be certain that the
incompatible protocols are available.  Ensuring that this information is correct
might need some amount of coordination in server deployments.  In particular,
coordination is important if a load balancer distributes load for a single IP
address to multiple server instances, or where anycast {{?BCP126}} is used.

Incompatible protocols can only be listed in the incompatible_protocols
extension when those protocols are deployed across all server instances.  A
client might regard lack of availability for an advertised protocol as a
downgrade attack, which could lead to service outages for those clients.

Server deployments can choose not to provide information about incompatible
protocols might avoid the operational complexity of providing accurate
information.  If a server does not list incompatible protocols, clients cannot
gain authenticated information about their availability and so cannot detect
downgrade attacks against those protocols.

During rollout of a new, incompatible protocol, until the deployment is stable
and not at risk of being disabled, servers SHOULD NOT advertise the existence of
the new protocol.

Protocol deployments that are in the process of being disabled first need to be
removed from the incompatible_protocols extension.  If a disabled protocol is
advertised to clients, clients might regard this as a downgrade attack.  Though
the incompatible_protocols extension only applies at the time of the TLS
handshake, clients might take some time to act on the information.  If an
incompatible protocol is removed from deployment between when the client
completes a handshake and when it acts, this could be treated as an error by the
client.


# Security Considerations

This design depends on the integrity of the TLS handshake across all forms,
including TLS {{?RFC8446}}, DTLS {{?DTLS=I-D.ietf-tls-dtls13}}, and QUIC
{{?QUIC-TLS=I-D.ietf-quic-tls}}.  Similarly, integrity is necessary across all
TLS versions that a client is willing to negotiate.  An attacker that can modify
a TLS handshake in any one of these protocols or versions can cause a client to
believe that other options do not exist.


# IANA Considerations

IANA is requested to assign a new value from the "TLS ExtensionType Values" registry:

Value:

: TBD

Extension Name:

: incompatible_protocols

TLS 1.3:

: CH, EE

DTLS-Only:

: N

Recommended:

: Y

Reference:

: this document, {{extension}}


--- back

# Acknowledgments

Benjamin Schwartz provided significant input into the design of the mechanism
and helped simplify the overall design.


# Defining Logical Servers

As incompatible protocols use different protocol stacks, they also use different
endpoints. In other words, it is impossible for a single endpoint to support
multiple incompatible protocols.  Thus, it is necessary to understand the set of
endpoints at a server that offer the incompatible protocols.

Thus, the definition of where incompatible protocols needs to encompass multiple
endpoints somehow.

A number of choices are possible here:

* The set of endpoints that are authoritative for the same domain name.

* The set of endpoints that are authoritative for the same "authority" as defined
  in RFC 3986 {{?URI=RFC3986}}, which is in effect domain name plus port number.

* The set of endpoints that are referenced by the same SVCB ServiceMode record;
  see {{Section 2.4.3 of SVCB}}.

* The set of endpoints that share an IP address.

* The set of endpoints that share an IP address and port number.

The challenge with options based on domain name is that it might prevent the use
of multiple service providers. This is a common practice for HTTP, where the
same domain name can be operated by multiple CDN operators.

Having multiple service operators also rules out using SVCB ServiceMode records
also as different records might be used to identify different operators.

Hosts on the same IP address might work, but common deployment practices include
use of different ports for entirely different services.  These can have
different operational constraints, such as deployment schedules.  Including
different ports in the same scope could force all services on the same host to
support a consistent set of protocols.

This leaves IP and port.  There is a risk that the same port number is used for
completely different purposes depending on the choice of protocol.  This
practice is sufficiently rare that it is not anticipated to be a problem.
Finally, a deployment with no ability to coordinate the deployment of protocols
that share an IP and port can choose not to advertise the availability of
incompatible protocols.
