# Caddy with the Route 53 DNS-01 module, so every node (including a passive
# failover node that receives no traffic) can hold a valid certificate for
# POAC_PUBLIC_HOST. Built once in CI and published to GHCR.
FROM caddy:2-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/route53

FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
