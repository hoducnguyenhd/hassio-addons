#!/usr/bin/with-contenv bashio

# Logs should include the date/time.
export __BASHIO_LOG_TIMESTAMP="%y-%m-%d %T"

if bashio::var.has_value "log_level"; then
  bashio::log.level "$(bashio::config 'log_level')"
fi

source /api_lib.sh

set +e

CERT_DIR=/data/letsencrypt

# Let's encrypt
LE_UPDATE="0"

# Config to variable
if bashio::config.has_value "ipv4"; then IPV4=$(bashio::config 'ipv4'); else IPV4="https://ipv4.text.wtfismyip.com"; fi
if bashio::config.has_value "ipv6"; then IPV6=$(bashio::config 'ipv6'); else IPV6="https://ipv6.text.wtfismyip.com"; fi
IPV4_="https://ifconfig.co/ip"
IPV6_="https://ifconfig.co/ip6"
DYNU_TOKEN=$(bashio::config 'dynu_token')
DUCK_TOKEN=$(bashio::config 'duck_token')
DOMAINS=$(bashio::config 'domains')
ALIASES=$(bashio::config 'aliases')
WAIT_TIME=$(bashio::config 'seconds')
WILDCARD=$(bashio::config 'wildcard_alias')

export Dynu_Token=$DYNU_TOKEN
export Duck_Token=$DUCK_TOKEN
bashio::log.debug "Dynu Token:" "$Dynu_Token"
bashio::log.debug "DuckDNS Token:" "$Duck_Token"
prv_ipv4=""
prv_ipv6=""

# Function to get the public IP
function get_public_ip() {
  [[ ${IPV4} != *:/* ]] && ipv4=${IPV4} || ipv4=$(curl -s -f -m 20 "${IPV4}") || ipv4=$(curl -s -f -m 20 "${IPV4_}") || ipv4=""
  [[ ${IPV6} != *:/* ]] && ipv6=${IPV6} || ipv6=$(curl -s -f -m 20 "${IPV6}") || ipv6=$(curl -s -f -m 20 "${IPV6_}") || ipv6=""
  bashio::log.debug "ipv4:" "$ipv4"
  bashio::log.debug "ipv6:" "$ipv6"

  if [ -z "$ipv4" ] ; then
    bashio::log.warning "Failed to get the current public IPv4!"
  else
    if [ "$ipv4" != "$prv_ipv4" ]; then
      bashio::log.info "IPv4 changed from $prv_ipv4 to $ipv4"
      prv_ipv4="$ipv4"
    fi
  fi

  if [ -z "$ipv6" ] ; then
    bashio::log.debug "Failed to get the current public IPv6!"
  else
    if [ "$ipv6" != "$prv_ipv6" ]; then
      bashio::log.info "IPv6 changed from $prv_ipv6 to $ipv6"
      prv_ipv6="$ipv6"
    fi
  fi
}

# Function to get domains in current certificate
function get_current_cert_domains() {
  cert_domains=$(openssl x509 -in /ssl/fullchain.pem -noout -text | grep -E 'DNS:' | sed 's/DNS://g; s/ //g')
  IFS=',' read -ra cert_domains_array <<< "$cert_domains"
}

# Function to get domains that should be included in the certificate
function get_domains_arrays() {
  domain_args=()
  main_domain_args=()
  domains_array=()
  main_domains_array=()
  aliases=''

  for domain in ${DOMAINS}; do
    for alias in $(jq --raw-output --exit-status "[.aliases[]|{(.alias):.domain}]|add.\"${domain}\" | select(. != null)" /data/options.json); do
      aliases="${aliases} ${alias}"
    done
  done

  aliases="$(echo "${aliases}" | tr ' ' '\n' | sort | uniq)"

  for domain in $(echo "${DOMAINS}" "${aliases}" | tr ' ' '\n' | sort | uniq); do
    # ===== PATCH: only SSL domains that support DNS-01 =====
    if [[ "$domain" == *"duckdns.org" ]] || [[ "$domain" == *"dynu.net" ]]; then
      domain_args+=("--domain" "${domain}")
      domains_array+=("${domain}")
      if [[ $domain != *"*."* ]]; then
        main_domain_args+=("--domain" "${domain}")
        main_domains_array+=("${domain}")
      fi
    else
      bashio::log.info "Skip SSL for unsupported domain: ${domain}"
    fi
    # ===== END PATCH =====
  done

  # Getting current domains included in current certificate
  get_current_cert_domains

  bashio::log.debug "cert_domains_array:" "${cert_domains_array[@]}"
  bashio::log.debug "domains_array:" "${domains_array[@]}"
  bashio::log.debug "domain_args:" "${domain_args[@]}"
  bashio::log.debug "main_domains_array:" "${main_domains_array[@]}"
  bashio::log.debug "main_domain_args:" "${main_domain_args[@]}"
}

# Function to get the epoch time after a month
function get_month_epoch() {
  current_time=$(date +%s)
  one_month=$((current_time + 30 * 24 * 60 * 60))
}

# Function to get the expiry date of the certificate
function get_cert_expiry() {
  expiration_date=$(openssl x509 -in /ssl/fullchain.pem -noout -dates -enddate | awk -F= '/notAfter/ {print $2}' 2> /dev/null)
  if [ $? -eq 0 ]; then
    expiry_epoch=$(date -D "%b %d %H:%M:%S %Y GMT" -d "$expiration_date" +"%s")
    return 0
  fi
  expiry_epoch=0
}

# Function that perform a renew
function le_renew() {
  get_cert_expiry
  get_month_epoch

  if [ "$expiry_epoch" -ge "$one_month" ] && [ "$domains_in_cert_match" = true ]; then
    LE_UPDATE="$(date +%s)"
    return 0
  fi

  bashio::log.info "Renew certificate for SSL-supported domains: ${main_domains_array[@]}"

  certbot certonly --force-renewal --manual --preferred-challenges dns --cert-name hass-cert \
    --manual-auth-hook /auth_script.sh \
    --manual-cleanup-hook /cleanup_script.sh \
    --register-unsafely-without-email --agree-tos \
    --deploy-hook /deploy_hook.sh \
    --non-interactive \
    ${main_domain_args[@]}

  LE_UPDATE="$(date +%s)"
}

########################
# main                 #
########################
get_public_ip
bashio::log.info "ipv4:" "$ipv4"
bashio::log.info "ipv6:" "$ipv6"

get_domains_arrays

domains_in_cert_match=true
if [ "${#cert_domains_array[@]}" -eq "${#domains_array[@]}" ]; then
  for cert_domain in "${cert_domains_array[@]}"; do
    if [[ ! " ${domains_array[@]} " =~ " $cert_domain " ]]; then
      domains_in_cert_match=false
      break
    fi
  done
else
  domains_in_cert_match=false
fi

if [ "$domains_in_cert_match" = false ]; then
  bashio::log.warning "Domains are changed, deleting old certificates in ${CERT_DIR}!!!!"
  rm -rf ${CERT_DIR}/*

  if bashio::config.true 'lets_encrypt.accept_terms'; then
    mkdir -p "${CERT_DIR}"
    certbot certonly --non-interactive \
      --register-unsafely-without-email --agree-tos \
      -d yourdomain.com &> /dev/null || true
  fi
fi

while true; do
  get_public_ip

  for domain in ${DOMAINS}; do
    if [[ $domain != *"*."* ]]; then
      if [[ $domain == *"duckdns.org" ]]; then
        [ -n "$ipv4" ] && curl -s -f "https://www.duckdns.org/update?domains=${domain}&token=${Duck_Token}&ip=${ipv4}" >/dev/null
        [ -n "$ipv6" ] && curl -s -f "https://www.duckdns.org/update?domains=${domain}&token=${Duck_Token}&ipv6=${ipv6}" >/dev/null
      else
        DynuDomainId=$(get_dynu_domain_id $domain $Dynu_Token)
        [ $? -eq 0 ] && curl -s -f -X POST -H "API-Key: ${Dynu_Token}" -H "Content-Type: application/json" \
          "https://api.dynu.com/v2/dns/${DynuDomainId}" \
          -d "{\"name\":\"$domain\",\"ipv4Address\":\"${ipv4}\",\"ipv6Address\":\"${ipv6}\"}"
      fi
    fi
  done

  now="$(date +%s)"
  if bashio::config.true 'lets_encrypt.accept_terms' && [ $((now - LE_UPDATE)) -ge 43200 ]; then
    le_renew
  fi

  sleep "${WAIT_TIME}"
done
