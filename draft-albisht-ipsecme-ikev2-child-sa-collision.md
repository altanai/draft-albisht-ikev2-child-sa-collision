---
title: "Collision Resolution for Simultaneous IKEv2 Child SA Creation"
abbrev: "IKEv2 Child SA Collision Resolution"
category: std

docname: draft-albisht-ipsecme-ikev2-child-sa-collision-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: sec
workgroup: IP Security Maintenance and Extensions
keyword:
 - IKEv2
 - IPsec
 - Child SA
 - collision resolution
venue:
  group: ipsecme
  type: Working Group
  mail: ipsec@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/ipsec/
  github: altanai/draft-albisht-ikev2-child-sa-collision

author:
 -
    fullname: Altanai Bisht
    organization: Cisco

normative:
  RFC7296:

informative:

...

--- abstract

This document specifies an opt-in procedure for resolving collisions when
both IKEv2 peers establish Child SAs for the same logical tunnel at about the
same time.  It defines a collision group, a deterministic candidate ranking,
and a state machine for selecting one Child SA candidate and cleaning up the
loser.  The procedure is intended for deployments that require one active
tunnel per configured peer relationship.  It does not change the IKEv2
behavior that permits multiple Child SAs with the same Traffic Selectors.

--- middle

# Introduction {#intro}

IKEv2 permits peers to establish multiple Child SAs between the same
endpoints.  This is useful in deployments that intentionally use parallel
SAs.  A different operational case occurs when two peers independently
initiate IKEv2 at nearly the same time, and each resulting IKE SA establishes
a Child SA for what the deployment intends to be one logical tunnel.  Without
a shared collision rule, each peer can retain a different IKE SA or Child SA,
or both can publish duplicate tunnel state.

{{RFC7296}} specifies nonce-based handling for simultaneous Child SA rekeying
and discusses simultaneous IKE SA rekeying.  It does not define a winner for
two independently initiated initial IKE SAs that each establish a Child SA.
This document proposes an opt-in collision-resolution procedure for that
case.  A collision is acted on only after the relevant peer is authenticated
and the Child SA is associated with the same configured collision group.

The procedure MUST NOT treat matching IP addresses or Traffic Selectors alone
as proof that two SAs are duplicates.  IKEv2 intentionally supports parallel
SAs with matching Traffic Selectors.  Deployments that need parallel SAs
MUST assign them distinct collision groups or leave collision resolution
disabled for them.

This document is an initial proposal for discussion in the IP Security
Maintenance and Extensions Working Group.  The IANA allocation and some
details of candidate-set synchronization remain to be agreed by the Working
Group.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** in this document
are to be interpreted as described in BCP 14 when, and only when, they appear
in all capitals.

## Definitions

**Collision group:** An administratively configured identifier for the set
of Child SAs for which the operator requires at most one selected candidate.
The identifier is scoped to an authenticated peer relationship and is not
derived from IP addresses or Traffic Selectors alone.

**Candidate:** An authenticated IKE SA and its associated Child SA that are
eligible to represent a collision group.

**Candidate rank:** A deterministic value computed from the IKE_SA_INIT
exchange that created a candidate.  Both peers have the inputs needed to
compute the same rank.

**Selected candidate:** The candidate with the highest rank among the
authenticated candidates known for a collision group.

# Protocol Overview

## Applicability and Opt-In

Collision resolution is enabled only when both peers support the procedure
and have configured the same collision group for the authenticated peer
relationship.  The group identifier is conveyed in an IKE_AUTH notification,
which is integrity-protected and encrypted.  A peer MUST NOT use an
unauthenticated IKE_SA_INIT packet as evidence that a collision group exists
or as a reason to delete an IKE SA or Child SA.

The precise Notify Message Type and payload format are not assigned in this
version of the proposal.  An implementation MUST NOT send an unassigned
Notify Message Type based on this document.

If either peer does not indicate support, the group identifiers do not
match, or authentication fails, the peers use normal IKEv2 behavior and do
not apply this collision procedure.  This preserves existing deployments
that intentionally establish parallel SAs.

## Candidate Identification

A candidate is eligible after:

1. The IKE SA has completed IKE_AUTH successfully.
2. Both peers have confirmed support and the same collision group.
3. A Child SA for that group has been successfully negotiated.

Retransmissions belonging to one IKE SA are one candidate.  A Child SA
created for a different group is outside this procedure.  If one IKE SA
carries Child SAs for multiple groups, selecting a candidate for one group
MUST NOT cause Child SAs in another group to be deleted.

## Candidate Ranking

Each candidate is ranked using the values from the IKE_SA_INIT exchange that
created its parent IKE SA.  The rank is the ordered tuple:

* the initiator nonce (Ni);
* the responder nonce (Nr);
* the initiator IKE SPI (SPIi); and
* the responder IKE SPI (SPIr); and
* a transcript digest (TD).

Tuple fields are compared in the order listed.  Nonces are compared as
octet strings in lexicographic order.  If one nonce is a prefix of the other,
the shorter nonce sorts first.  SPI fields are compared as unsigned
big-endian integers.  The transcript digest is compared as an octet string
in lexicographic order.  The candidate with the higher tuple is selected;
the candidate with the lower tuple is the loser.

TD is computed as `SHA-256(Request || Response)`, where `Request` and
`Response` are the successful IKE_SA_INIT request and response that created
the candidate IKE SA, in that order.  Each input is the complete encoded IKE
message, including its IKE header and payloads but excluding the IP and UDP
headers.  The request is the request corresponding to the successful
response (including any COOKIE payload used in that request).  This
definition gives both peers the same byte strings to hash.
The fixed-length digest provides a deterministic final tie-break when Ni,
Nr, SPIi, and SPIr are equal but other IKE_SA_INIT message contents differ.

If the SPI pair is already present in the candidate set, it identifies the
same IKE SA candidate and MUST NOT be treated as a separate candidate.  If
two candidate records nevertheless have identical ranking tuples, they are
equivalent for ranking and MUST be treated as one candidate; implementations
MUST NOT choose between them using local timestamps, local IKE unique IDs,
or arrival order.

The ranking values are shared by both peers and are bound to the authenticated
IKE exchange.  Implementations MUST NOT use local timestamps, local IKE
unique IDs, or arrival order as a tie-break, because those values can differ
between peers.

This rule is inspired by the nonce comparison used for simultaneous Child SA
rekeying in RFC 7296, Section 2.8.1.  The rule here applies to the initial
IKE_SA_INIT exchanges that created separate candidate IKE SAs; it does not
reinterpret the RFC 7296 rekey procedure.

## Candidate-Set Synchronization

When entering `ARBITRATING`, each peer needs to learn which authenticated
candidates the other peer has observed.  The proposed mechanism is an
integrity-protected collision-status notification sent on each eligible IKE
SA.  It identifies the collision group and lists the candidate IKE SPI pairs
known to the sender.  The receiver merges the list with its local candidate
set and returns its current set.  Retransmission and duplicate notifications
are handled idempotently.

The notification encoding, acknowledgement rule, and treatment of a
candidate that authenticates after a peer reports its candidate set are
open protocol details.  The final specification needs to define them before
an implementation can claim interoperable collision resolution.

## State Machine

The state machine is maintained independently for each collision group.

~~~
[IDLE] -- local start or admit peer IKE exchange --> [NEGOTIATING]

[NEGOTIATING] -- second authenticated candidate for same group --> [ARBITRATING]
[NEGOTIATING] -- one candidate; no admitted exchange pending --> [ESTABLISHED]
[ESTABLISHED] -- late candidate from admitted exchange --> [ARBITRATING]

[ARBITRATING] -- rank candidates; select winner --> [CLEANUP]
[CLEANUP] -- loser deleted; winner retained --> [ESTABLISHED]
[CLEANUP] -- deletion fails --> [CLEANUP] (retry; keep same winner)

[ESTABLISHED] -- winner lost --> [IDLE] (recover)
[Any state] -- no eligible candidate remains --> [IDLE]
~~~

`NEGOTIATING` covers both a locally initiated IKE exchange and an admitted
incoming exchange while a Child SA is being created.  If a second
authenticated candidate is found for the same group, the machine enters
`ARBITRATING`, including when an exchange admitted before establishment
completes later.

In `ARBITRATING`, the implementation computes the rank of every known
eligible candidate.  It MUST retain a stable selected candidate while loser
cleanup is retried.  A cleanup failure MUST NOT, by itself, cause the peers
to select a different candidate.

In `CLEANUP`, the endpoint that owns the losing Child SA SHOULD delete it
using the normal IKEv2 deletion procedure.  The implementation MUST NOT
delete an IKE SA that carries Child SAs outside the losing collision group.
Cleanup is idempotent: an already-absent losing Child SA counts as removed.
A cleanup failure MUST cause a retry with the same winner; it MUST NOT cause
the peers to swap winners.

## Tunnel Publication

An implementation that uses this procedure to prevent duplicate tunnels
MUST gate tunnel publication on candidate selection.  Only the selected
candidate may be published as the active tunnel for a collision group.
Implementations SHOULD avoid forwarding traffic on an unselected candidate
while arbitration is in progress.

Because IKE messages can be delayed or lost, a peer might learn about a
candidate after it has locally selected another candidate.  In that case it
MUST re-enter `ARBITRATING`, recompute the winner over the expanded candidate
set, and remove the loser.  This procedure guarantees deterministic
convergence once both peers know the same authenticated candidate set; it
does not guarantee that no transient duplicate IKE SA exists during
negotiation or message delay.

# Example Call Flows

Peers A and B are configured for the same collision group. `X` denotes
the IKE SA initiated by A and `Y` the IKE SA initiated by B. `C_X` and
`C_Y` are the corresponding Child SA pairs. `INIT` abbreviates
`IKE_SA_INIT`, and `AUTH` abbreviates `IKE_AUTH`. The examples omit
payloads unrelated to collision resolution. Candidate-set agreement is
shown as a condition because its wire encoding and acknowledgement rules
are still open.

## Simultaneous IKE_SA_INIT

~~~
Peer A                                                 Peer B
  |--- INIT request X (SPIi_X, 0, Ni_X) ---------------->|
  |<-- INIT request Y (SPIi_Y, 0, Ni_Y) -----------------|
  |<-- INIT response X (SPIi_X, SPIr_X, Nr_X) -----------|
  |--- INIT response Y (SPIi_Y, SPIr_Y, Nr_Y) ---------->|
  |--- AUTH request X ---------------------------------->|
  |<-- AUTH request Y -----------------------------------|
  |<-- AUTH response X (C_X) ----------------------------|
  |--- AUTH response Y (C_Y) --------------------------->|
  |                                                      |
  |    AUTH completes on X and Y at both peers.          |
  |    Both peers confirm the same collision group.      |
  |    Once both know {X, Y}, both rank Y above X.       |
  |    Both select C_Y. Cleanup targets C_X.             |
~~~

Each peer initiates one exchange and responds to the other. The two INIT
requests cross while both exchanges are in `NEGOTIATING`. At this point
neither exchange is eligible for arbitration. Even if both peers can
compute the ranks from INIT, they wait for authentication, group
confirmation, and successful Child SA negotiation. The example assumes
`rank(Y) > rank(X)`, so both peers make the same selection when their
eligible candidate sets agree and then enter `CLEANUP`.

## Asymmetric IKE_AUTH Completion

Here `X` becomes eligible at both peers first. A completes its responder
processing for `Y`, but the final AUTH response on `Y` is lost.

~~~
Peer A                                                 Peer B
  |    AUTH on X completes at both peers.                |
  |<-- AUTH request Y -----------------------------------|
  |--- AUTH response Y (C_Y) -----X    (lost)            |
  |    Eligible at A: {X, Y}       Eligible at B: {X}    |
  |                                                      |
  |<-- Retransmit AUTH request Y ------------------------|
  |--- Cached AUTH response Y (C_Y) -------------------->|
  |    Eligible at A: {X, Y}       Eligible at B: {X, Y} |
  |                                                      |
  |    Once both know {X, Y}, both select C_Y.           |
  |    Cleanup targets C_X.                              |
~~~

During the gap, A enters `ARBITRATING` and ranks `Y` above `X` locally
while B is still negotiating `Y`. Deleting `C_X` based on A's local
rank would remove B's only eligible Child SA. An SPI pair
advertised by the peer does not make `Y` locally eligible at B. In this
example, A defers cleanup until both peers know `Y` is eligible. The
retransmitted request and cached response use the same IKE SA and Message
ID and add no candidates. If `Y` never becomes eligible at B, this path
never reaches the shared selection of `C_Y` that triggers deletion of
`C_X`.

## Incoming and Crossed Child SA Deletes

Both examples start after the peers agree that `C_Y` is selected and
`C_X` is the loser. `x_A` is the inbound SPI of `C_X` at A, and `x_B`
is its inbound SPI at B. Each Delete names the sender's inbound SPI.
`SK {}` denotes an empty encrypted INFORMATIONAL response. All messages
shown here use the authenticated IKE SA `X`. See RFC 7296, Section 1.4.1,
for Delete processing.

### Incoming Delete Before Local Cleanup

~~~
Peer A                                                 Peer B
  |--- INFORMATIONAL request: SK { Delete(x_A) } ------->|
  |<-- INFORMATIONAL response: SK { Delete(x_B) } -------|
  |                                                      |
  |    C_X removed at both peers. C_Y remains selected.  |
~~~

B closes its outbound half of `C_X` identified by `x_A` and returns
the paired inbound SPI `x_B`. A processes the response and completes
deletion of `C_X`. When B's collision cleanup runs, the already-absent
`C_X` counts as removed.

### Crossed Deletes for the Same Child SA Pair

~~~
Peer A                                                 Peer B
  |--- INFORMATIONAL request: SK { Delete(x_A) } ------->|
  |<-- INFORMATIONAL request: SK { Delete(x_B) } --------|
  |<-- INFORMATIONAL response to A's request: SK {} -----|
  |--- INFORMATIONAL response to B's request: SK {} ---->|
  |                                                      |
  |    C_X removed at both peers. C_Y remains selected.  |
~~~

Each peer has already sent a Delete for its inbound half of `C_X`. Each
closes its outbound half when processing the peer's request and its
inbound half when processing the response to its own request. Neither
response carries a Delete payload for `C_X`. Retransmissions are handled
as part of the original INFORMATIONAL exchange.

An authenticated Delete for the selected Child SA is handled by normal
IKEv2 processing. Loss of the selected candidate invokes recovery in the
collision state machine. An IKE SA Delete also closes its remaining Child
SAs. Collision cleanup therefore targets the losing Child SA when its
parent IKE SA carries Child SAs outside the losing group.

# Security Considerations {#security}

An unauthenticated IKE_SA_INIT packet can be forged.  Implementations MUST
NOT tear down an established IKE SA or Child SA based only on such a packet.
Collision membership and candidate ranking are acted upon only after IKE_AUTH
has authenticated the peer and confirmed the collision group.

The collision group is an administrative scope.  An overly broad group can
cause valid parallel Child SAs to be deleted.  Implementations SHOULD expose
the group as explicit policy and SHOULD NOT infer it solely from matching
Traffic Selectors, IP addresses, or peer identity.

The ranking rule selects one candidate; it does not provide authorization or
prefer a more trusted cryptographic suite.  Normal IKEv2 authentication,
proposal policy, and authorization checks MUST be completed before a
candidate participates in arbitration.

An authenticated peer can influence the nonce values it contributes to an
IKE_SA_INIT exchange.  The ranking rule is intended to make both peers
converge, not to provide fairness against a malicious authenticated peer.
Implementations MUST continue to apply rate limits and resource controls to
IKE negotiation and collision cleanup.

Candidate-set synchronization and late candidate discovery can cause a
temporary disagreement about the selected candidate.  Implementations
SHOULD hold publication until arbitration has progressed sufficiently to
reduce this risk, and MUST re-arbitrate when a new eligible candidate is
discovered.

# IANA Considerations {#iana}

This document has no IANA actions in this version.  A future version that
specifies the IKEv2 Notify payloads will request the required Notify Message
Type allocation from the IANA IKEv2 Parameters registry.

--- back

# Acknowledgments
{:numbered="false"}

The author thanks the IKEv2 and IPsecME communities for their review and
feedback.  The proposal was motivated in part by implementation experience
with an IKE initiation state machine.
