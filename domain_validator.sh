#!/usr/bin/env bash
# Domain Setup Validator
# Usage: ./domain_validator.sh domain [expected_ip] [expected_cname]
# Requires: dig, curl, openssl, date (GNU date recommended)

set -u

if [ $# -lt 1 ]; then
  echo "Usage: $0 domain [expected_ip] [expected_cname]"
  exit 2
fi

DOMAIN="$1"
EXPECTED_IP="${2-}"
EXPECTED_CNAME="${3-}"

# check dependencies
for cmd in dig curl openssl date; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Dependency missing: $cmd. Install it and retry."; exit 3; }
done

ok_dns=true
ok_https=true
ok_cert=true

echo "=== DNS checks for: $DOMAIN ==="
A_RECORDS=$(dig +short A "$DOMAIN")
CNAME_RECORD=$(dig +short CNAME "$DOMAIN")

if [ -z "$A_RECORDS" ] && [ -z "$CNAME_RECORD" ]; then
  echo "ERROR: No A or CNAME records found for $DOMAIN"
  ok_dns=false
else
  echo "A records:"
  if [ -n "$A_RECORDS" ]; then echo "$A_RECORDS"; else echo "(none)"; fi
  echo "CNAME: ${CNAME_RECORD:-(none)}"
fi

# verify expected IP if provided
if [ -n "$EXPECTED_IP" ]; then
  if echo "$A_RECORDS" | grep -xFq "$EXPECTED_IP"; then
    echo "OK: Expected IP $EXPECTED_IP present in A records."
  else
    echo "ERROR: Expected IP $EXPECTED_IP NOT found in A records."
    ok_dns=false
  fi
fi

# verify expected CNAME if provided
if [ -n "$EXPECTED_CNAME" ]; then
  # remove trailing dots for comparison
  norm_cname=$(echo "${CNAME_RECORD:-}" | sed 's/\.$//')
  norm_expected=$(echo "$EXPECTED_CNAME" | sed 's/\.$//')
  if [ "$norm_cname" = "$norm_expected" ]; then
    echo "OK: CNAME matches expected ($EXPECTED_CNAME)."
  else
    echo "ERROR: CNAME does not match expected. Found: '${CNAME_RECORD:-none}'"
    ok_dns=false
  fi
fi

echo
echo "=== HTTPS (curl) check ==="
curl_out=$(curl -sS --max-time 10 -I "https://$DOMAIN" -o /dev/null -w "%{http_code}" 2>/dev/null)
curl_status=$?
if [ $curl_status -ne 0 ]; then
  echo "ERROR: curl failed to connect to https://$DOMAIN (exit $curl_status)"
  ok_https=false
else
  echo "HTTP status code from HTTPS endpoint: $curl_out"
  if [ "$curl_out" -ge 400 ]; then
    echo "ERROR: HTTPS endpoint returned HTTP $curl_out"
    ok_https=false
  else
    echo "OK: HTTPS endpoint reachable (HTTP $curl_out)."
  fi
fi

echo
echo "=== TLS certificate (openssl) check ==="
# fetch certificate text
cert_text=$(echo | openssl s_client -connect "${DOMAIN}:443" -servername "$DOMAIN" 2>/dev/null)
if [ -z "$cert_text" ]; then
  echo "ERROR: openssl couldn't fetch certificate from ${DOMAIN}:443"
  ok_cert=false
else
  enddate_line=$(printf "%s" "$cert_text" | openssl x509 -noout -enddate 2>/dev/null)
  if [ -z "$enddate_line" ]; then
    echo "ERROR: No certificate found / cannot parse end date."
    ok_cert=false
  else
    enddate_val="${enddate_line#notAfter=}"
    echo "Certificate notAfter: $enddate_val"
    # compute days left (GNU date required)
    if expiry_epoch=$(date -d "$enddate_val" +%s 2>/dev/null); then
      now_epoch=$(date +%s)
      days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
      echo "Days until certificate expiry: $days_left"
      if [ $days_left -lt 0 ]; then
        echo "ERROR: Certificate has expired."
        ok_cert=false
      fi
    else
      echo "WARNING: Could not parse certificate date with 'date -d'. (On macOS use 'gdate' from coreutils or use Python checker.)"
      # do not fail solely for date parsing; continue to SAN check
    fi
  fi

  # get SANs (if any)
  san_list=$(printf "%s" "$cert_text" | openssl x509 -noout -text 2>/dev/null | grep -o 'DNS:[^,]*' | sed 's/DNS://g' | tr '\n' ' ')
  if [ -z "$san_list" ]; then
    # fallback to CN
    cn=$(printf "%s" "$cert_text" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN=//p')
    if [ -n "$cn" ]; then
      san_list="$cn"
    fi
  fi

  echo "Certificate SAN/CN: ${san_list:-(none)}"

  # check whether the cert covers the domain (exact or wildcard)
  cover=false
  for san in $san_list; do
    if [ "$san" = "$DOMAIN" ]; then cover=true; break; fi
    # wildcard match (e.g. *.example.com matches foo.example.com)
    case "$san" in
      \*.*)
        suf="${san#*.}"
        case "$DOMAIN" in
          *."$suf") cover=true; break;;
        esac
      ;;
    esac
  done

  if $cover; then
    echo "OK: Certificate covers domain $DOMAIN (SAN/CN matched)."
  else
    echo "ERROR: Certificate does NOT cover domain $DOMAIN."
    ok_cert=false
  fi
fi

echo
echo "=== Summary ==="
if $ok_dns && $ok_https && $ok_cert; then
  echo "Setup Complete"
  exit 0
else
  echo "Setup NOT complete. Problems found:"
  $ok_dns || echo "- DNS checks failed"
  $ok_https || echo "- HTTPS endpoint check failed"
  $ok_cert || echo "- Certificate validation failed"
  exit 1
fi
