---
title: The Privacy Pass Protocol
abbrev: PP protocol
docname: draft-privacy-pass-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Davidson
    name: Alex Davidson
    org: Cloudflare Portugal
    street: Largo Rafael Bordalo Pinheiro 29
    city: Lisbon
    country: Portugal
    email: alex.davidson92@gmail.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare
    street: 101 Townsend Street
    city: San Francisco
    country: United States of America
    email: nick@cloudflare.com

normative:
  RFC2119:
  TRUST:
    title: Trust Token API
    target: https://github.com/WICG/trust-token-api#security-considerations
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://www.degruyter.com/view/j/popets.2018.2018.issue-3/popets-2018-0026/popets-2018-0026.xml
    authors:
      -
        ins: A. Davidson
        org: RHUL, UK
      -
        ins: I. Goldberg
        org: University of Waterloo, Canada
      -
        ins: N. Sullivan
        org: Cloudflare, CA, USA
      -
        ins: G. Tankersley
        org: Independent
      -
        ins: F. Valsorda
        org: Independent
  OPRF:
    title: Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
    target: https://tools.ietf.org/html/draft-irrf-cfrg-voprf-01
    authors:
      -
        ins: A. Davidson
        org: Cloudflare, UK
      -
        ins: N. Sullivan
        org: Cloudflare, US
      -
        ins: C. Wood
        org: Apple Inc.
  PPEXT:
    title: Privacy Pass Browser Extension
    target: https://github.com/privacypass/challenge-bypass-extension
  PPSRV:
    title: Cloudflare Supports Privacy Pass
    target: https://blog.cloudflare.com/cloudflare-supports-privacy-pass/
  DSS:
    title: "FIPS PUB 186-4: Digital Signature Standard (DSS)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    author:
      -
        ins: Federal Information Processing Standards Publication
  keytrans:
    title: "Security Through Transparency"
    target: https://security.googleblog.com/2017/01/security-through-transparency.html
    authors:
      -
        ins: Ryan Hurst
        org: Google
      -
        ins: Gary Belvin
        org: Google

--- abstract

This document specifies the Privacy Pass protocol for anonymously
authorizing clients with services on the Internet.

--- middle

# Introduction {#intro}

In some situations, it may only be necessary to check that a client has been
previously authorized by a service; without learning any other information.
Such lightweight authorization mechanisms can be useful in quickly assessing
the reputation of a client in latency-sensitive communication.

The Privacy Pass protocol was initially introduced as a mechanism for reauthorizing clients 
that had already been authorized in the past using anonymous tokens, or credentials, without 
compromizing their privacy {{DGSTV18}}. The protocol has two primary security properties: unlinkability 
and one-more-token security. Briefly, unlinkability means that servers cannot link 
an individual client's original authorization and reauthorization requests. One-more-token
security means that a client cannot generate tokens for reauthorization on its own.
See {{security}} for more details.

The Privacy Pass protocol is split into the following an offline and online phase. 
In the offline phase, known as Initialization, servers are configured with necessary 
cryptographic keying material needed for the remainder of the protocol and clients
obtain this keying material. The online phase is composed of two sub-protocols,
Issuance and Redemption, described below:

1. Issuance: In this phase, a client and server run a protocol wherein clients receive
as output an anonymous credential and servers learn nothing.
2. Redemption: In this phase, a client reveals information which proves a prior Issuance protocol
invocation took place, including, for example, secret inputs used for Issuance and the 
resulting anonymous credential. Servers learn nothing beyond proof of prior Issuance completion.

This document specifies a single instance of the Privacy Pass protocol based on the VOPRF
construction. In this variant, the Initialisation and Issuance phases corresponding to 
the setup and issuance phases of the VOPRF in {{OPRF}}. In doing so, this document also 
specifies cryptographic operations required by the underlying VOPRF, along with recommendations 
for cryptographic key rotation. This protocol instance is designed for applications which 
require efficient and lightweight reauthorization checks.

The Privacy Pass protocol is designed to allow other cryptographic algorithms for token 
token creation and verification in the Issuance and Redemption phases, respectively. 

The remainder of the document is organized as follows:

- {{overview}}: A generic overview of the Privacy Pass protocol based on VOPRFs.
- {{registry}}: Describes the format of trusted registries that are used for
  holding public key commitments for each of the Privacy Pass issuers.
- {{configurations}}: Details different configurations for using the Privacy
  Pass protocol.
- {{privacy}}: Privacy considerations and recommendations arising from the usage
  of the Privacy Pass protocol.
- {{security}}: Additional security considerations to prevent abuse of the
  protocol from a malicious client.
- {{params}}: A summary of recommended parameter settings for ensuring privacy
  and security features of the protocol.

## Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP14 {{!RFC2119}} {{!RFC8174}}  when, and only when, they appear in
all capitals, as shown here.

# Conventions and Terminology

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- VOPRF: Verifiable Oblivious PRF {{OPRF}}.
- Server: A service that provides access to a certain resource (typically
  denoted S).
- Client: An entity that seeks authorization from a server (typically denoted C)
- Key: Server VOPRF key.
- Commitment: Corresponding public key to server's VOPRF key.



Certain parts of the protocol are parameterized by cryptographic groups, elements,
or quantities. Below is a table of these items.

| Symbol | Meaning | Relevance |
|:------:|---------|-----------|

| l | XXX | XXX |
| p | An integer prime number | XXX |
| r | Order of G | XXX |

| G | An abelian group | XXX |




Throughout this draft, let D be some object corresponding to an opaque data type
(such as a group element). We write bytes(D) to denote the encoding of this data
type as raw bytes (octet strings). We assume that such objects can also be
interpreted as Buffer objects, with each internal slot in the buffer set to the
value of the one of the bytes. For two objects x and y, we denote the
concatenation of the bytes of these objects by (bytes(x) .. bytes(y)). We assume
that all bytes are first base64-encoded before they are sent as part of a
protocol message.

We use the notation `[ Ti ]` to indicate an array of objects T1, ... , TQ where
the size of the array is Q, and the size of Q is implicit from context.

## Elliptic curve points

When encoding elliptic curve points into existing data structures or into
protocol messages, we assume that the curve points are first encoded into bytes.
We allow both uncompressed and compressed encodings, as long as the client and
server are aligned on the encodings that they used. Compressed encodings provide
storage and communication benefits but are slightly more expensive to decode.

## Protocol messages

Protocol messages can either be encoded in raw byte format, as base64-encoded
string objects, or as JSON objects where all strings are represented in
base64-encoded format.

# Protocol overview {#overview}

In this section, we present a broad overview of the Privacy Pass protocol. Fundamentally,
Privacy Pass is a protocol designed for anonymous authentication between
client and server. In particular, it allows for clients to publicly authenticate
to a server -- during the protocol Issuance phase -- and receive anonymous
credentials for future use. Clients can then later use these tokens in the 
Redemption phase as a form of anonymous authentication, asserting they previously
completed the Issuance phase. 

As mentioned in {{intro}}, the generic protocol can be split into an online an 
offline phase. The offline Initialization and online Issuance phases correspond 
to the setup and issuance phases of the VOPRF in {{OPRF}}. The last phase, Redemption, 
corresponds to the client revealing their secret input data during the VOPRF protocol 
to the server. The server can use this data to confirm that the client has a valid 
VOPRF output, without being able to link the data to any individual issuance phase.

Throughout this document, we adhere to the recommendations laid out in {{OPRF}}
in integrating the VOPRF protocol into our wider workflow. Where necessary, we
lay out exactly which part of the VOPRF API we use. We stress that the
generalized protocol only includes steps and messages that contain cryptographic
data.

We decide against defining abstract interfaces for enclosing Privacy Pass
data and functionality. Instead, we describe the Privacy Pass protocol in the
same group setting that is used in {{OPRF}}.

## Offline Initialisation phase

In the Initialisation phase, servers run the Setup and KeyGen algorithms corresponding to
the desired ciphersuite to produce group parameters and a corresponding private key. Setup is
a deterministic function, so the parameters do not change per invocation.
For VOPRF ciphersuites, this amounts to running the Setup algorithm defined in {{OPRF}},
which produces a private key k and cryptographic group generator. Given a key k,
a server then creates a PrivacyPassKeyPackage structure of the form below.

~~~
struct {
    uint16 cpiphersite; 
    opaque public_key<0..2^16-1>;
    uint64 expiry_date_timestamp;
    opaque signature<0..2^16-1>;
} PrivacyPassKeyPackage;
~~~

: public_key
The public key used in the PrivacyPass protocol, corresponding to the private key k.

: expiry_date:
The NTP timestamp {{RFC5905}} corresponding to when the corresponding public_key expires.
It is RECOMMENDED that each key has a lifetime between 1 and 6 months.

: signature
The ASN1-encoded signature evaluated over the contents of the PrivacyPassKeyPackage struct.

Clients obtain a copy of the server's PrivacyPassKeyPackage structure either directly
from the server or via some other means. {{registry}} discusses the possibility of uploading 
public key material to a trusted registry that client's access when communicating with
the server.

## Online phases

### Issuance phase

In the Issuance phase, a client and server run the VOPRF evaluation protocol
from {{OPRF}} given client input x and server private key k corresponding to 
the public key in PrivacyPassKeyPackage. In particular, a client C generates an
IssuanceRequest message (as described below) and receives an IssuanceResponse
message from a server S. These messages have the following structure.

~~~
struct {
  uint8 issuance_type;
  opaque context<0..2^8-1>;
  select (IssuanceRequest.issuance_type) {
    case single_request: {
      opaque blinded_input<0..2^16-1>;
    }
    case batched_request: {
      uint8 batch_count;
      opaque blinded_inputs<0..2^16-1>;
    }
  }
} IssuanceRequest;

struct {
  uint8 issuance_type;
  opaque context<0..2^8-1>;
  select (IssuanceRequest.issuance_type) {
    case single_request: {
      opaque signed_output<0..2^16-1>;
    } 
    case batched_request: {
      opaque signed_outputs<0..2^16-1>;
    }
} IssuanceResponse; 
~~~

The Issuance protocol runs as follows:

1. C computes x' = Commit(x), (M, r) = Blind(x'), constructs an IssuanceRequest
with IssuanceRequest.issuance_type = 0x01, unique IssuanceRequest.context value,
and IssuanceRequest.blinded_input = M. C sends IssuanceRequest to S.
2. On an input request IssuanceRequest of type 0x01, S computes Z = Evaluate(k, IssuanceRequest.M), 
constructs an IssuanceResponse with matching type and context and 
IssuanceResponse.signed_output = Z. S sends IssuanceResponse to C.
3. On an input response IssuanceResponse with matching context, C computes 
N = Unblind(IssuanceResponse.Z, r), y = Finalize(x', N), and returns y.

C determines the underlying VOPRF ciphersuite from PrivacyPassKeyPackage.ciphersuite.
C stores the Issuance input and output tuple (x, y) as the anonymous credential from 
this evaluation.

In the last step of the Issuance phase, the client runs Finalize and store the output. 
Some applications may need to link the output of Finalize to the future subsequent
Redemption phase. To achieve this, clients SHOULD tailor the `aux` data to something
specific to the Issuance phase just run.

#### Batched Issuance phase

Clients and servers may run the Issuance phase in batch mode, wherein a client sends multiple 
blinded values to a server in a single round. This avoids a single round trip per token and 
also permits more efficient VOPRF proof construction. Let B be the batch count for a given 
invocation of this protocol. This modified phase works as follows:

1. C computes xi' = Commit(xi) and (Mi, ri) = Blind(xi') for i = 1,...,B. C then
constructs an IssuanceRequest with IssuanceRequest.issuance_type = 0x02, unique 
IssuanceRequest.context value, and IssuanceRequest.blinded_inputs to the concenation
of M1,...,MB.
2. On an input request IssuanceRequest of type 0x02, S parses IssuanceRequest.blinded_inputs as
B = IssuanceRequest.batch_count elements M1,...,MB, and computes Zi = Evaluate(k, Mi) for 1 = 1,..,B.
S creates an IssuanceResponse with matching type and context, and 
IssuanceResponse.signed_outputs = Z1,...,ZB.
3. On an input response IssuanceResponse with matching type and context, C parses 
IssuanceResponse.signed_outputs as B signed outputs, Z1,...,ZB, and then computes
Ni = Unblind(IssuanceResponse.Zi, ri), yi = Finalize(xi', Ni), and returns 
((x1, y1), ..., (xB, yB)).

### Redemption phase

In the Redemption phase, the client uses an anonymous token (x, y) as an authenticator
to the server. This is packaged in the following RedemptionRequest structure:

~~~
struct {
  opaque input<0..2^16-1>;
  opaque output<0..2^16-1>;
} RedemptionRequest;
~~~

The Redemption phase between client C to server S using anonymous token (x, y) works 
as follows.

1. C creates a RedemptionRequest with RedemptionRequest.input = x and RedemptionRequest.output = y, and
sends RedemptionRequest to S.
2. On input redemption request RedemptionRequest, S computes x' = Commit(RedemptionRequest.x), 
N' = Evaluate(k, x'), and y' = Finalize(x', N'). S accepts the credential if 
y' = RedemptionRequest.y. Otherwise, it rejects the credential.

For protection against clients re-using anonymous credentials, servers SHOULD store previously 
used (and accepted) inputs. A Bloom filter suffices for this purposes. Moreover, this storage
should be bound to the lifetime of the public key. After key rotation, servers SHOULD erase
any previous client input state.

# Key registration {#registry}

Rather than sending the result of the key initialisation procedure directly to
each client, it is preferable to upload the object obj to a trusted,
tamper-proof, history-preserving registry. By trusted, we mean from the
perspective of clients that use the Privacy Pass protocol. Any new keys uploaded
to the registry should be appended to the list. Any keys that have expired can
optionally be labelled as so, but should never be removed. A trusted registry
may hold key commitments for multiple Privacy Pass service providers (servers).

Clients can either choose to:

- poll the trusted registry and import new keys, rejecting any that throw
  errors;
- retrieve the commitments for the server at the time at which they are used,
  throwing errors if no valid commitment is available.

To prevent unauthorized modification of the trusted registry, server's should be
required to identify and authenticate themselves before they can append data to
their configuration. Moreover, only parts of the registry that correspond to the
servers configuration can be modifiable.

The registry that we describe could be fulfilled by Key Transparency
{{keytrans}} or other similar architectures.

## Key rotation

Whenever a server seeks to rotate their key, they must append their key to the
trusted registry. We recommend that the trusted registry is arranged as a JSON
blob with a member for each JSON provider. Each provider appends new keys by
creating a new sub-member corresponding to an incremented version label along
with their new commitment object.

Concretely, we recommend that the trusted registry is a JSON file of the form
below.

~~~ json
  {
    "server_1": {
      "ciphersuite": ...,
      "batchsize": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    }
    "server_2": {
      "ciphersuite": ...,
      "batchsize": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    },
    ...
  }
~~~

In this structure, "server_1" and "server_2" are separate service providers. The
sub-member "ciphersuite" corresponds to the choice of VOPRF ciphersuite made by
the server. The sub-members "1.0", "1.1" of "server_1" correspond to the
versions of commitments available to the client. Increasing version numbers
should correspond to newer keys. Each commitment should be a valid encoding of a
point corresponding to the group in the VOPRF ciphersuite specified in
"ciphersuite". The "batchsize" is the maximum number of tokens it will sign in a
batched issuance instantiation.

If "server_2" wants to upload a new commitment with version tag "1.1", it runs
the key initialisation procedure from above and adds a new sub-member "1.1" with
the value set to the value of the output obj. The "server_2" member should now
take the form below.

~~~ json
  {
    ...
    "server_2": {
      "ciphersuite": ...,
      "batchsize": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
    },
    ...
  }
~~~


## Client retrieval

We define a function `retrieve(server_id, version_id)` which retrieves the
commitment with version label equal to version_id, for the provider denoted by
the string server_id. For example, retrieve("server_1","1.1") will retrieve the
member labelled with "1.1" above.

We implicitly assume that this function performs the following verification
checks:

~~~ lua
  if (!ECDSA.verify(ecdsaVK, obj.Y .. bytes(obj.expiry)) {
    return "error"
  } else if (!(new Date() < obj.expiry)) {
    return "error"
  }
~~~

If `error` is not returned, then it instead returns the entire object. We also
abuse notation and also use `ciph = retrieve(server_id, "ciphersuite")` to refer
to retrieving the ciphersuite for the server configuration.

## Key revocation

If a server must revoke a key, then it uses a separate member with label
`revoke` corresponding to an array of revoke versions associated with key
commitments. In the above example, if `server_2` needs to revoke the key with
version `1.0`, then it appends a new `revoke` member with the array `[ "1.0" ]`.
Any future revocations can simply be appended to this array. For an example, see
below.

~~~ json
  {
    ...
    "server_2": {
      "ciphersuite": ...,
      "1.0": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "1.1": {
        "Y": ...,
        "expiry": ...,
        "sig": ...,
      },
      "revoked": [ "1.0" ],
    },
    ...
  }
~~~

Client's are required to check the `revoked` member for new additions when they
poll the trusted registry for new key data.

## VOPRF ciphersuites

We strongly RECOMMEND that a server uses only one VOPRF ciphersuite at any one
time. Should a server choose to change some aspect of the ciphersuite (e.g., the
group instantiation or other cryptographic functionality) we further RECOMMEND
that the server create a new identifying label (e.g.
`server_1_${ciphersuite_id}`) where ciphersuite_id corresponds to the identifier
of the VOPRF ciphersuite. Then `server_1` revokes all keys for the previous
ciphersuite and then only offers commitments for the current label.

An alternative arrangement would be to add a new layer of members between server
identifiers and key versions in the JSON struct, corresponding to
`ciphersuite_id`. Then the client may choose commitments from the appropriate
group identifying member.

We strongly recommend that service providers only operate with one group
instantiation at any one time. If a server uses two VOPRF ciphersuites at any
one time then this may become an avenue for segregating the user-base. User
segregation can lead to privacy concerns relating to the utility of the
obliviousness of the VOPRF protocol (as raised in {{OPRF}}). We discuss this
more in {{privacy}}.

## ECDSA key material

For clients must also know the verification (ecdsaVK) for each service provider
that they support. This enables the client to verify that the commitment is
properly formed before it uses it. We do not provide any specific
recommendations on how the client has access to this key, beyond that the
verification key should be accessible separately from the trusted registry.

While the number of service providers associated with Privacy Pass is low, the
client can simply hardcode the verification keys directly for each provider that
they support. This may be cumbersome if a provider wants to rotate their signing
key, but since these keys should be comparatively long-term (relative to the
VOPRF key schedule), then this should not be too much of an issue.

# Protocol configurations {#configurations}

We provide an overview of some of the possible ways of configuring the Privacy
Pass protocol situation, such that it can be used as a lightweight trust
attestation mechanism for clients.

## Single-Issuer Single-Verifier {#sisv}

The simplest way of considering the Privacy Pass protocol is in a setting where
the same server plays the role of issuer and verifier, we call this
"Single-Issuer Single-Verifier" (SISV). In SISV, we consider a server S that
publishes commitments for their secret key k, that a client C has access to.

When S wants to issue tokens to C, they invoke the issuance protocol where C
generates their own inputs and S uses their secret key k. In this setting, C can
only perform token redemption with S. When a token redemption is required, C and
S invoke the redemption phase of the protocol, where C uses an issued token from
a previous exchange, and S uses k as their input again.

In SISV, C proves that S has attested to the honesty of C at some point in the
past (without revealing exactly when). S can use this information to inform it's
own decision-making about C without having to recompute the trust attestation
task again.

## Single-Issuer Forwarding-Verifier {#sifv}

In this setting, each client C obtains issued tokens from a server S via the
issuance phase of the protocol. The difference is that clients can prove that S
has attested to their honesty in the past with any verifier V. We still only
consider S to hold their own secret key.

When C interacts with V, V can ask C to provide proof that the separate issuer S
has attested to their trust. The first stage of the redemption phase of the
protocol is invoked between C and V, which sees C send the unused token
(x,y,aux) to V. This message is then used in a redemption exchange between V and
S, where V plays the role of the client. Then S sends the result of the
redemption exchange to V, and V uses this result to determine whether C has the
correct trust attestation.

This configuration is known as "Single-Issuer Forwarding-Verifier" or SIFV to
refer to the verifier V who uses the output of the redemption phase for their
own decision-making.

## Single-Issue Asynchronous-Verifier {#siav}

This setting is inspired by recently proposed APIs such as {{TRUST}}. It is
similar to the SIFV configuration, except that the verifiers V no longer
interact with the issuer S. Only C interacts with S, and this is done
asynchronously to the trust attestation request from V. Hence
"Asynchronous-Verifier" (SIAV).

When V invokes a redemption for C, C then invokes a redemption exchange with S
in a separate session. If verification is carried out successfully by S, S
instead returns a Signed Redemption Record (SRR) that contains the following
information:

~~~ json
"result": {
  "timestamp":"2019-10-09-11:06:11",
  "verifier": "V",
},
"signature":sig,
~~~

The `signature` field carries a signature evaluated over the contents of
`result` using a long-term signing key for the issuer S, of which the
corresponding public key is well-known to C and V. Then C can prove that their
trust attestation from S to V by sending the SRR to V. The SRR can be verified
by V by verifying the signature using the well-known public key for S.

Such records can be cached to display again in the future. The issuer can also
add an expiry date to the record to determine when the client must refresh the
record.

## Bounded-Issuers {#bi-config}

Each of the configurations above can be generalized to settings where a bounded
number of issuers are allowed, and verifiers can invoke trust attestations for
any of the available issuers. Subsequently, this leads to three new
configurations known as BISV, BIFV, BIAV.

As we will discuss later in {{issuers}}, configuring a large number of issuers
can lead to privacy concerns for the clients in the ecosystem. Therefore, we are
careful to ensure that the number of issuers is kept strictly bounded by a fixed
small number M. The actual issuers can be replaced with different issuers as
long as the total never exceeds M. Moreover, issuer replacements also have an
effect on client privacy that is similar to when a key rotation occurs, so
replacement should only be permitted at similar intervals.

See {{issuers}} for more details about safe choices of M.

### Fixing the bound

Configuring any number of issuers greater than 1 effectively reduces privacy by
an extra bit. As a result, we see an exponential decrease in privacy in the
number of issuers that are currently active. Therefore the value of M should be
kept very low (we recommend no higher than 4).

# Privacy considerations {#privacy}

We intentionally encode no special information into redemption tokens to prevent
a vendor from learning anything about the client. We also have cryptographic
guarantees via the VOPRF construction that a vendor can learn nothing about a
client beyond which issuers trust it. Still there are ways that malicious
servers can try and learn identifying information about clients that it
interacts with.

We discuss a number of privacy considerations made in {{OPRF}} that are relevant
to the Privacy Pass protocol use-case, along with additional considerations
arising from the specific ways of using the Privacy Pass protocol in
{{configurations}}.

## User segregation {#segregation}

An inherent features of using cryptographic primitives like VOPRFs is that any
client can only remain private relative to the entire space of users using the
protocol. In principle, we would hope that the server can link any client
redemption to any specific issuance invocation with a probability that is
equivalent to guessing. However, in practice, the server can increase this
probability using a number of techniques that can segregate the user space into
smaller sets.

### Key rotation

As introduced in {{OPRF}}, such techniques to introduce segregation are closely
linked to the type of key schedule used by the server. When a server rotates
their key, any client that invokes the issuance protocol shortly afterwards will
be part of a small number of possible clients that can redeem. To mechanize this
attack strategy, a server could introduce a fast key rotation policy which would
force clients into small key windows. This would mean that client privacy would
only have utility with respect to the smaller group of users that have Trust
Tokens for a particular key window.

In the {{OPRF}} draft it is recommended that great care is taken over key
rotations, in particular server's should only invoke key rotation for fairly
large periods of time such as between 1 and 12 months. Key rotations represent a
trade-off between client privacy and continued server security. Therefore, it is
still important that key rotations occur on a fairly regular cycle to reduce the
harmfulness of a server key compromise.

Trusted registries for holding Privacy Pass key commitments can be useful in
policing the key schedule that a server uses. Each key must have a corresponding
commitment in this registry so that clients can verify issuance responses from
servers. Clients may choose to inspect the history of the registry before first
accepting redemption tokens from the server. If a server has updated the
registry with many unexpired keys, or in very quick intervals a client can
choose to reject the tokens.

TODO: Can client's flag bad server practices?

### Large numbers of issuers {#issuers}

Similarly to the key rotation issue raised above, if there are a large number of
issuers, similar user segregation can occur. In the BISV, BIFV, BIAV
configurations of using the Privacy Pass protocol ({{configurations}}), a
verifier OV can trigger redemptions for any of the available issuers. Each
redemption token that a client holds essentially corresponds to a bit of
information about the client that OV can learn. Therefore, there is an
exponential loss in privacy relative to the number of issuers that there are.

For example, if there are 32 issuers, then OV learns 32 bits of information
about the client. If the distribution of issuer trust is anything close to a
uniform distribution, then this is likely to uniquely identify any client
amongst all other Internet users. Assuming a uniform distribution is clearly the
worst-case scenario, and unlikely to be accurate, but it provides a stark
warning against allowing too many issuers at any one time.

As we noted in {{bi-config}}, a strict bound should be applied to the active
number of issuers that are allowed at one time. We propose that allowing no more
than 6 issuers at any one time is highly preferable (leading to a maximum of 64
possible user segregations). Issuer replacements should only occur with the same
frequency as key rotations as they can lead to similar losses in privacy if
users still hold redemption tokens for previously active issuers.

In addition, we recommend that trusted registries indicate at all times which
issuers are deemed to be active. If a client is asked to invoke any Privacy Pass
exchange for an issuer that is not declared active, then the client should
refuse to participate in the protocol.

#### Selected trusted registries

One recommendation is that only a fixed number (TODO: how many?) of issuers are
sanctioned to provide redemption tokens at any one time. This could be enforced
by the trusted registry that is being used. Client's can then choose which
registries to trust and only accept redemption tokens from issuers accepted into
those registries.

#### Maximum number of issuers inferred by client

A second recommendation is that clients only store redemption tokens for a fixed
number of issuers at any one time. This would prevent a malicious verifier from
being able to invoke redemptions for many issuers since the client would only be
holding redemption tokens for a small set of issuers. When a client is issued
tokens from a new issuer and already has tokens from the maximum number of
issuers, it simply deletes the oldest set of redemption tokens in storage and
then stores the newly acquired tokens.

## Tracking and identity leakage

While redemption tokens themselves encode no information about the client
redeeming them, there may be problems if we allow too many redemptions on a
single page. For instance, the first-party cookie for user U on domain A can be
encoded in the trust token information channel and decoded on domain B, allowing
domain B to learn the user's domain A cookie until either first-party cookie is
cleared. Mitigations for this issue are similar to those proposed in {{issuers}}
for tackling the problem of having large number of issuers.

In SIAV, cached SRRs and their associated issuer public keys have a similar
tracking potential to first party cookies in the browser setting. Therefore
these should be clearable by the client using standard deletion methods.

# Security considerations {#security}

The Privacy Pass instantiation in this document has the following security properties:

- Unlinkability: The Evaluation and Redemption phases are completely independent. This means
a server cannot link a Redemption flow to a specific prior Evaluation flow. This property
is limited by protocol messages exchanged between client and server. Other linkability 
vectors exist, e.g., a client IP address.
- One-more-token security: A client cannot forge new anonymous credentials given any
of its existing tokens without access to the server's private key.

In the following sections, we present a number of security considerations that prevent a 
malicious actors from abusing the protocol.

## Double-spend protection

All issuing server should implement a robust storage-query mechanism for
checking that tokens sent by clients have not been spent before. Such tokens
only need to be checked for each issuer individually. But all issuers must
perform global double-spend checks to avoid clients from exploiting the
possibility of spending tokens more than once against distributed token checking
systems. For the same reason, the global data storage must have quick update
times. While an update is occurring it may be possible for a malicious client to
spend a token more than once.

## Key rotation

We highlighted previously that short key-cycles can be used to reduce client
privacy. However, regular key rotations are still recommended to maintain good
server key hygiene. The key material that we consider to be important are:

- the VOPRF key;
- the signing key used to sign commitment information;
- the signing key used to sign SRRs in the SIAV configuration.

In summary, our recommendations are that VOPRF keys are rotated from anywhere
between a month and a single year. With an active user-base, a month gives a
fairly large window for clients to participate in the Privacy Pass protocol and
thus enjoy the privacy guarantees of being part of a larger group. The low
ceiling of a year prevents a key compromise from being too destructive. If a
server realizes that a key compromise has occurred then the server should revoke
the previous key in the trusted registry and specify a new key to be used.

For the two signing keys, these should both be well-known keys associated with
the issuer (TODO: where should they be stored?). Issuers may choose to use the
same key for both signing purposes. The rotation schedules for these keys can be
much longer, if necessary.

## Token exhaustion

When a client holds tokens for an issuer, it is possible for any verifier to
invoke that client to redeem tokens for that issuer. This can lead to an attack
where a malicious verifier can force a client to spend all of their tokens for a
given issuer. To prevent this from happening, methods should be put into place
to prevent many tokens from being redeemed at once.

For example, it may be possible to cache a redemption for the entity that is
invoking a token redemption. In SISV/SIFV, if the verifier requests more tokens
then the client simply returns the cached token that it returned previously.
This could also be handled by simply not redeeming any tokens for the entity if
a redemption had already occurred in a given time window.

In SIAV, the client instead caches the SRR that it received in the asynchronous
redemption exchange with the issuer. If the same verifier attempts another trust
attestation request, then the client simply returns the cached SRR. The SRRs can
be revoked by the issuer, if need be, by providing an expiry date or by
signaling that records from a particular window need to be refreshed.

# Summary of privacy and security parameters {#params}

We provide a summary of the parameters that we use in the Privacy Pass protocol.
These parameters are informed by both privacy and security considerations that
are highlighted in {{privacy}} and {{security}}, respectively. These parameters
are intended as a single reference point for implementers when implementing the
protocol.

Firstly, let U be the total number of users, I be the total number of issuers.
Assuming that each user accept tokens from a uniform sampling of all the
possible issuers, as a worst-case analysis, this segregates users into a total
of 2^I buckets. As such, we see an exponential reduction in the size of the
anonymity set for any given user. This allows us to specify the privacy
constraints of the protocol below, relative to the setting of A.

| parameter | value |
|---|---|
| Minimum anonymity set size (A) | 5000 |
| Recommended key lifetime (L) | 1 - 6 months |
| Recommended key rotation frequency (F) | L/2 |
| Maximum allowed issuers (I) | log_2(U/A)-1 |
| Maximum active issuance keys | 1 |
| Maximum active redemption keys | 2 |
| Minimum security parameter | 196 bits |

## Justification

We make the following assumptions in these parameter choices.

- Inferring the identity of a user in a 5000-strong anonymity set is difficult
- After 2 weeks, all clients in a system will have rotated to the new key

The maximum choice of I is based on the equation 1/2 * U/2^I = A. This is
because I issuers lead to 2^I segregations of the total user-base U. By reducing
I we limit the possibility of performing the attacks mentioned in
{{segregation}}.

We must also account for each user holding issued data for more then one
possible active keys. While this may also be a vector for monitoring the access
patterns of clients, it is likely to unavoidable that clients hold valid
issuance data for the previous key epoch. This also means that the server can
continue to verify redemption data for a previously used key. This makes the
rotation period much smoother for clients.

For privacy reasons, it is recommended that key epochs are chosen that limit
clients to holding issuance data for a maximum of two keys. By choosing F = L/2
then the minimum value of F is 1/2 a month, since the minimum recommended value
of L is 1 month. Therefore, by the initial assumption, then all users should
only have access to only two keys at any given time. This reduces the anonymity
set by another half at most.

Finally, the minimum security parameter size is related to the cryptographic
security offered by the group instantiation that is chosen. For example, if we
use an elliptic curve over a 256-bit prime field, then the actual group
instantiation offers 128 bits of security (or a security parameter of size 128
bits). However, as noted in {{OPRF}}, OPRF protocols reduce the effective
security of the group by log_2(M) where M is the number of queries. As such, we
choose the minimum size of the security parameter to be 196 bits, so that it is
difficult for a malicious client to exploit this.

## Example parameterization

Using the specification above, we can give some example parameterizations. For
example, the current Privacy Pass browser extension {{PPEXT}} has over 150,000
active users (from Chrome and Firefox). Then log_2(U/A) is approximately 5 and
so the maximum value of I should be 4.

If the value of U is much bigger (e.g. 5 million) then this would permit I =
log_2(5000000/5000)-1 = 8 issuers.
