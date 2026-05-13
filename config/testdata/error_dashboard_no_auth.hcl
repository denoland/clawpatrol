# info_listen + empty dashboard_secret + no insecure opt-out is a
# silent misconfig: the gateway runs but every dashboard request
# hits a "dashboard auth not configured" page. Surface it at load
# time instead.

listen      = "0.0.0.0:8443"
info_listen = "0.0.0.0:8080"
