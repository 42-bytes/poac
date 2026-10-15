# Egress sidecar for the verifier: forward proxy that admits ONE destination,
# the AWS KMS endpoint of the configured region, over CONNECT/443. Everything
# else is denied, nothing is cached. The verifier stays on the internal
# (no-route) network and reaches this proxy via HTTPS_PROXY.
# __REGION__ is substituted from POAC_KMS_REGION at container start.

http_port 3128
pid_filename none
cache deny all
access_log stdio:/dev/stdout
cache_log /dev/stderr
logfile_rotate 0
via off
forwarded_for delete
dns_v4_first on

acl kms dstdomain kms.__REGION__.amazonaws.com
acl SSL_ports port 443
acl CONNECT method CONNECT

http_access allow CONNECT kms SSL_ports
http_access deny all
