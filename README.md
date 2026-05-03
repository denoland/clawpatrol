
```
curl -fsSL https://denoland.github.io/clawpatrol-go/install.sh | sh
```

```
clawpatrol gateway init --admin-email you@example.com

Detected public IP: 203.0.113.10
├ Generated CA at /etc/clawpatrol/ca/ca.crt
├ Wrote /etc/clawpatrol/gateway.hcl
├ Opened udp/51820 + tcp/9080
└ Wrote /etc/systemd/system/clawpatrol-gateway.service

Dashboard: http://gw.example.com:9080
Join command: clawpatrol join --url http://gw.example.com:9080
```

```
clawpatrol join --url http://gw.example.com:9080

Verify code in browser:

    ABCD-1234

http://gw.example.com:9080/onboard/ABCD-1234

⠧ Waiting for approval
Approved.
├ Joined as 10.55.0.7
├ CA installed in system trust
└ Shell rc: eval "$(clawpatrol env)"

Installed! Try: clawpatrol run claude
```
