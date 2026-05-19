# dashboard_operators entries must be "user@domain" or "*@domain".
# A bare username or a misshapen wildcard ("foo*@bar") would either
# silently fail to match the intended whois login or match too
# broadly, so the loader refuses it instead of warning.

listen      = "0.0.0.0:8443"
info_listen = "127.0.0.1:8080"

dashboard_operators = ["bert"]
