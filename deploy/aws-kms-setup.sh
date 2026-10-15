#!/usr/bin/env bash
# Create the PoAC issuer keys in AWS KMS and a least-privilege signer identity
# for the verifier host. Idempotent: re-running finds existing aliases/users.
#
# Run from a machine with admin AWS credentials (your laptop):
#   AWS_PROFILE=poac-admin ./deploy/aws-kms-setup.sh
#
# Creates:
#   KMS key  alias/poac-issuer-ed25519   ECC_NIST_EDWARDS25519  (receipt signing, default)
#   KMS key  alias/poac-issuer-mldsa65   ML_DSA_65              (post-quantum co-signature)
#   IAM user poac-verifier-signer with ONLY kms:Sign + kms:GetPublicKey on those two keys
#   one access key for that user -> printed once, goes into /opt/poac/.env on the server
#
# Nothing here can export private key material; KMS does not allow it.
set -euo pipefail

REGION="${AWS_REGION:-eu-north-1}"
export AWS_DEFAULT_REGION="$REGION"
SIGNER_USER="${SIGNER_USER:-poac-verifier-signer}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "account=$ACCOUNT_ID region=$REGION"

ensure_key() {  # alias keyspec description -> key id
  local alias="alias/$1" spec="$2" desc="$3" id
  if id=$(aws kms describe-key --key-id "$alias" --query KeyMetadata.KeyId --output text 2>/dev/null); then
    echo "exists  $alias -> $id" >&2
  else
    id=$(aws kms create-key --key-spec "$spec" --key-usage SIGN_VERIFY \
          --description "$desc" --tags TagKey=project,TagValue=poac \
          --query KeyMetadata.KeyId --output text)
    aws kms create-alias --alias-name "$alias" --target-key-id "$id"
    echo "created $alias -> $id" >&2
  fi
  echo "$id"
}

ED_ID=$(ensure_key poac-issuer-ed25519 ECC_NIST_EDWARDS25519 "PoAC receipt issuer (Ed25519, JWS alg EdDSA)")
PQ_ID=$(ensure_key poac-issuer-mldsa65 ML_DSA_65 "PoAC receipt issuer (ML-DSA-65, JWS alg ML-DSA-65, RFC 9964)")
ED_ARN="arn:aws:kms:$REGION:$ACCOUNT_ID:key/$ED_ID"
PQ_ARN="arn:aws:kms:$REGION:$ACCOUNT_ID:key/$PQ_ID"

# --- signer identity: can sign and read public keys, nothing else -------------
if ! aws iam get-user --user-name "$SIGNER_USER" >/dev/null 2>&1; then
  aws iam create-user --user-name "$SIGNER_USER" --tags Key=project,Value=poac >/dev/null
  echo "created IAM user $SIGNER_USER" >&2
fi
POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SignReceipts",
    "Effect": "Allow",
    "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
    "Resource": ["$ED_ARN", "$PQ_ARN"]
  }]
}
EOF
)
aws iam put-user-policy --user-name "$SIGNER_USER" --policy-name poac-sign-only \
  --policy-document "$POLICY_DOC"
echo "attached inline policy poac-sign-only (Sign/GetPublicKey/DescribeKey on 2 keys)" >&2

# --- key policy: root admin + signer can sign; nobody can ScheduleKeyDeletion
#     without the admin path. (Default key policy already grants the account
#     root full access; we just add the signer explicitly for clarity.)
for ARN in "$ED_ARN" "$PQ_ARN"; do
  KEY_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Id": "poac-issuer",
  "Statement": [
    {"Sid": "AccountAdmin", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::$ACCOUNT_ID:root"},
     "Action": "kms:*", "Resource": "*"},
    {"Sid": "VerifierSign", "Effect": "Allow",
     "Principal": {"AWS": "arn:aws:iam::$ACCOUNT_ID:user/$SIGNER_USER"},
     "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*"}
  ]
}
EOF
)
  aws kms put-key-policy --key-id "$ARN" --policy-name default --policy "$KEY_POLICY"
done

# --- one access key, printed once ----------------------------------------------
EXISTING=$(aws iam list-access-keys --user-name "$SIGNER_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
if [ -n "$EXISTING" ]; then
  echo "signer already has access key(s): $EXISTING — not creating another." >&2
  echo "   (to rotate: aws iam delete-access-key --user-name $SIGNER_USER --access-key-id <id>, then rerun)" >&2
else
  CREDS=$(aws iam create-access-key --user-name "$SIGNER_USER" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
  AK=$(echo "$CREDS" | cut -f1); SK=$(echo "$CREDS" | cut -f2)
  cat <<EOF

================ add to /opt/poac/.env on the verifier host (shown ONCE) ================
POAC_KMS_REGION=$REGION
POAC_KMS_ED25519_KEY=$ED_ARN
POAC_KMS_MLDSA65_KEY=$PQ_ARN
AWS_ACCESS_KEY_ID=$AK
AWS_SECRET_ACCESS_KEY=$SK
==========================================================================================
EOF
fi

echo
echo "public keys (safe to share):"
aws kms get-public-key --key-id "$ED_ARN" --query '[KeySpec,SigningAlgorithms]' --output text
aws kms get-public-key --key-id "$PQ_ARN" --query '[KeySpec,SigningAlgorithms]' --output text
