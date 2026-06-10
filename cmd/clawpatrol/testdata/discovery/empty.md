# Claw Patrol access manifest — profile: empty

You are connected through the Claw Patrol gateway. It intercepts your
connections transparently: dial the hosts below as you normally would and
the gateway injects credentials and enforces policy. A credential
`placeholder` is a literal string you send where the secret would go — the
gateway swaps it for the real secret. This manifest is scoped to YOUR
device profile; it lists only what this profile grants.

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

