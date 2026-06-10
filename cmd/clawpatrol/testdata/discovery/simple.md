# Claw Patrol access manifest — profile: simple

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

TLS is intercepted. The gateway terminates TLS for every host you dial —
it is a transparent man-in-the-middle. The certificate you see for an
upstream is minted on the fly by Claw Patrol's own certificate authority,
not the host's real public certificate: the hostname matches but the
issuer is the gateway CA. Trust that CA to verify these connections —
fetch it from https://clawpatrol/ca.crt and check its fingerprint against
https://clawpatrol/info. A certificate-authority mismatch against the
public web PKI is expected here, not an attack.

## Endpoints (1)

### github  (https)

- Host(s): api.github.com
- Credential: bearer_token `gh` — send placeholder `PH_GH`
- Example: `curl https://api.github.com/ -H "Authorization: Bearer PH_GH"`

