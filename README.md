
```
curl -fsSL https://denoland.github.io/clawpatrol-go/install.sh | sh
```

```
clawpatrol gateway init --admin-email you@example.com

Detected public IP: 66.42.120.196
├ Generated CA at /etc/clawpatrol/ca/ca.crt
├ Wrote /etc/clawpatrol/gateway.hcl
├ Opened udp/51820 + tcp/9080
⎿ Wrote /etc/systemd/system/clawpatrol-gateway.service

Dashboard: http://66.42.120.196:9080
Join command: clawpatrol join --url http://66.42.120.196:9080
```

```
clawpatrol join --url http://66.42.120.196:9080

Open and approve:
├ http://66.42.120.196:9080/onboard/ABCD1234
⎿ Code: ABCD-1234

........
Approved.
├ Joined as 10.55.0.7
├ CA installed in system trust
⎿ Shell rc: eval "$(clawpatrol env)"

Next: clawpatrol run -- claude
```
