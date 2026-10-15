#!/usr/bin/env bash
# Active-passive failover for the PoAC verifier (plan R):
#   - Lightsail secondary node (Stockholm) with a static IP
#   - Route 53 hosted zone for POAC_PUBLIC_HOST (delegated from the parent
#     DNS with NS records), failover A records + HTTPS health checks
#   - IAM user `poac-dns01` that may only edit records in that zone (used by
#     Caddy for ACME DNS-01 on both nodes)
# Idempotent. Run from a machine with admin AWS credentials:
#   PRIMARY_IP=37.27.146.243 AWS_PROFILE=poac-admin deploy/aws-failover-setup.sh
set -euo pipefail

REGION="${AWS_REGION:-eu-north-1}"
export AWS_DEFAULT_REGION="$REGION"
HOST="${POAC_PUBLIC_HOST:-poac.42bytes.eu}"
PRIMARY_IP="${PRIMARY_IP:?set PRIMARY_IP (current Hetzner node)}"
INSTANCE="${INSTANCE:-poac-secondary}"
BUNDLE="${BUNDLE:-nano_3_0}"          # $5: 1 GB / 2 vCPU / 40 GB
BLUEPRINT="${BLUEPRINT:-ubuntu_24_04}"
AZ="${AZ:-${REGION}a}"
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/poac_hetzner.pub}"
DNS_USER="${DNS_USER:-poac-dns01}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "account=$ACCOUNT_ID region=$REGION host=$HOST"

# --- Lightsail node ---------------------------------------------------------------
if ! aws lightsail get-key-pair --key-pair-name poac >/dev/null 2>&1; then
  aws lightsail import-key-pair --key-pair-name poac --public-key-base64 "$(base64 <"$SSH_PUBKEY" | tr -d '\n')" >/dev/null
  echo "imported ssh key pair 'poac'" >&2
fi
if ! aws lightsail get-instance --instance-name "$INSTANCE" >/dev/null 2>&1; then
  aws lightsail create-instances --instance-names "$INSTANCE" --availability-zone "$AZ" \
    --blueprint-id "$BLUEPRINT" --bundle-id "$BUNDLE" --key-pair-name poac \
    --tags key=project,value=poac >/dev/null
  echo "creating Lightsail $INSTANCE ($BUNDLE, $AZ)…" >&2
  until [ "$(aws lightsail get-instance --instance-name "$INSTANCE" --query 'instance.state.name' --output text)" = "running" ]; do sleep 5; done
fi
if ! aws lightsail get-static-ip --static-ip-name "$INSTANCE-ip" >/dev/null 2>&1; then
  aws lightsail allocate-static-ip --static-ip-name "$INSTANCE-ip" >/dev/null
fi
if [ "$(aws lightsail get-static-ip --static-ip-name "$INSTANCE-ip" --query 'staticIp.attachedTo' --output text)" != "$INSTANCE" ]; then
  aws lightsail attach-static-ip --static-ip-name "$INSTANCE-ip" --instance-name "$INSTANCE" >/dev/null
fi
SECONDARY_IP=$(aws lightsail get-static-ip --static-ip-name "$INSTANCE-ip" --query 'staticIp.ipAddress' --output text)
aws lightsail put-instance-public-ports --instance-name "$INSTANCE" --port-infos \
  'fromPort=22,toPort=22,protocol=tcp' 'fromPort=80,toPort=80,protocol=tcp' \
  'fromPort=443,toPort=443,protocol=tcp' 'fromPort=443,toPort=443,protocol=udp' >/dev/null
echo "secondary: $INSTANCE $SECONDARY_IP (ssh ubuntu@$SECONDARY_IP)" >&2

# --- Route 53 zone -----------------------------------------------------------------
ZONE_ID=$(aws route53 list-hosted-zones-by-name --dns-name "$HOST." --max-items 1 \
  --query "HostedZones[?Name=='$HOST.'].Id | [0]" --output text 2>/dev/null | sed 's|/hostedzone/||')
if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "None" ]; then
  ZONE_ID=$(aws route53 create-hosted-zone --name "$HOST" --caller-reference "poac-$(date +%s)" \
    --hosted-zone-config Comment="PoAC verifier failover zone" --query 'HostedZone.Id' --output text | sed 's|/hostedzone/||')
  echo "created hosted zone $ZONE_ID" >&2
fi
NS=$(aws route53 get-hosted-zone --id "$ZONE_ID" --query 'DelegationSet.NameServers' --output text)

# --- health checks (by IP, HTTPS, SNI + Host = the public name) ----------------------
ensure_hc() {  # ip -> health check id
  local ip="$1" id
  id=$(aws route53 list-health-checks --query "HealthChecks[?HealthCheckConfig.IPAddress=='$ip' && HealthCheckConfig.FullyQualifiedDomainName=='$HOST'].Id | [0]" --output text)
  if [ -z "$id" ] || [ "$id" = "None" ]; then
    id=$(aws route53 create-health-check --caller-reference "poac-$ip-$(date +%s)" --health-check-config \
      "IPAddress=$ip,Port=443,Type=HTTPS,ResourcePath=/.well-known/jwks.json,FullyQualifiedDomainName=$HOST,RequestInterval=30,FailureThreshold=2,EnableSNI=true" \
      --query 'HealthCheck.Id' --output text)
    aws route53 change-tags-for-resource --resource-type healthcheck --resource-id "$id" \
      --add-tags Key=Name,Value="poac $ip" Key=project,Value=poac >/dev/null
  fi
  echo "$id"
}
HC_PRIMARY=$(ensure_hc "$PRIMARY_IP")
HC_SECONDARY=$(ensure_hc "$SECONDARY_IP")

# --- failover records --------------------------------------------------------------
CHANGE=$(cat <<EOF
{"Changes":[
 {"Action":"UPSERT","ResourceRecordSet":{"Name":"$HOST","Type":"A","SetIdentifier":"primary","Failover":"PRIMARY",
   "TTL":60,"ResourceRecords":[{"Value":"$PRIMARY_IP"}],"HealthCheckId":"$HC_PRIMARY"}},
 {"Action":"UPSERT","ResourceRecordSet":{"Name":"$HOST","Type":"A","SetIdentifier":"secondary","Failover":"SECONDARY",
   "TTL":60,"ResourceRecords":[{"Value":"$SECONDARY_IP"}],"HealthCheckId":"$HC_SECONDARY"}},
 {"Action":"UPSERT","ResourceRecordSet":{"Name":"a.$HOST","Type":"A","TTL":300,"ResourceRecords":[{"Value":"$PRIMARY_IP"}]}},
 {"Action":"UPSERT","ResourceRecordSet":{"Name":"b.$HOST","Type":"A","TTL":300,"ResourceRecords":[{"Value":"$SECONDARY_IP"}]}}
]}
EOF
)
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch "$CHANGE" >/dev/null
echo "failover records set: PRIMARY $PRIMARY_IP, SECONDARY $SECONDARY_IP (a./b. = direct names)" >&2

# --- DNS-01 user, scoped to this zone --------------------------------------------------
if ! aws iam get-user --user-name "$DNS_USER" >/dev/null 2>&1; then
  aws iam create-user --user-name "$DNS_USER" --tags Key=project,Value=poac >/dev/null
fi
aws iam put-user-policy --user-name "$DNS_USER" --policy-name poac-dns01-zone --policy-document "$(cat <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["route53:ListHostedZones","route53:ListHostedZonesByName","route53:GetChange"],"Resource":"*"},
 {"Effect":"Allow","Action":["route53:ChangeResourceRecordSets","route53:ListResourceRecordSets"],
  "Resource":"arn:aws:route53:::hostedzone/$ZONE_ID",
  "Condition":{"ForAllValues:StringEquals":{"route53:ChangeResourceRecordSetsRecordTypes":["TXT"]}}}
]}
EOF
)"
EXISTING=$(aws iam list-access-keys --user-name "$DNS_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
if [ -z "$EXISTING" ]; then
  CREDS=$(aws iam create-access-key --user-name "$DNS_USER" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
  AK=$(echo "$CREDS" | cut -f1); SK=$(echo "$CREDS" | cut -f2)
  cat <<EOF

================ add to /opt/poac/.env on BOTH nodes (shown ONCE) ================
POAC_DNS_ZONE_ID=$ZONE_ID
POAC_DNS_ACCESS_KEY_ID=$AK
POAC_DNS_SECRET_ACCESS_KEY=$SK
====================================================================================
EOF
else
  echo "dns01 user already has access key(s): $EXISTING — not creating another. POAC_DNS_ZONE_ID=$ZONE_ID" >&2
fi

cat <<EOF

NEXT (parent DNS, e.g. Cloudflare): delete the A record for '$HOST' and add
these NS records for the name '${HOST%%.*}' (DNS only, not proxied):
$(echo "$NS" | tr '\t' '\n' | sed 's/^/  NS  /')
EOF
