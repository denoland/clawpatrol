# Claw Patrol access manifest — profile: empty

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

TLS is intercepted only for the hosts this profile grants — the
endpoints listed below. For those, the gateway terminates TLS and acts
as a transparent man-in-the-middle: the certificate you see is minted on
the fly by Claw Patrol's own certificate authority, not the host's real
public certificate. The hostname matches but the issuer is the gateway
CA. Trust that CA to verify these connections — fetch it from
https://clawpatrol/ca.crt and check its fingerprint against
https://clawpatrol/info. A certificate-authority mismatch against the
public web PKI is expected for these hosts, not an attack.

Every other host is passed through untouched: the gateway does not
intercept it, you get the upstream's real certificate, and you must
still verify it against the public web PKI as usual.

## This profile is empty

Your device is mapped to the `empty` profile, which currently grants no
endpoints and no credentials. That's why there's nothing actionable
below. This is a configuration state, not an error — the gateway is
reachable, your device just hasn't been granted anything yet.

To get value from Claw Patrol, this profile needs endpoints and the
credentials to reach them bound to it. An operator does that in the
dashboard by either assigning this device a profile that already grants
what you need, or adding endpoints and credentials to this one.

Ask the person who runs this gateway to open the dashboard at https://gw.example.test
and update this device's profile.

Once the profile is configured, re-fetch this manifest (GET
https://clawpatrol/) and the endpoints and credentials will appear below.

## Endpoints (0)

_None reachable for this profile._

