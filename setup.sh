#!/usr/bin/env bash
# Configura e gestisce il worker Cloudflare "private-dns" (DoH + adblock + anti-tracking).
#
#   ./setup.sh [deploy]        setup completo (KV, token, deploy, secrets, blocklist)
#   ./setup.sh lists           ricompila le blocklist in locale e le carica su KV
#   ./setup.sh update          chiede al worker di ricompilare le liste (serve piano Paid)
#   ./setup.sh block  <dom..>  blocca dei domini (e sottodomini)
#   ./setup.sh allow  <dom..>  sblocca dei domini (whitelist)
#   ./setup.sh unrule <dom..>  rimuove regole personalizzate
#   ./setup.sh rules           mostra le regole personalizzate
#   ./setup.sh check <dominio> verifica se un dominio è bloccato
#   ./setup.sh status          stato del worker / numero di domini caricati
#   ./setup.sh info            mostra gli URL DoH e il profilo Apple
#
# Variabili opzionali: WORKER_NAME (default private-dns), CUSTOM_DOMAIN (es. dns.example.com),
# CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID (per uso non interattivo), BLOCKLISTS (URL separati da virgola).
set -euo pipefail

cd "$(dirname "$0")"
WORKER_NAME="${WORKER_NAME:-private-dns}"
STATE_FILE=".private-dns.env"
WR="npx --yes wrangler@4"

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_dim=$'\e[2m'; c_off=$'\e[0m'
log()  { echo "${c_ok}▶${c_off} $*"; }
warn() { echo "${c_dim}  $*${c_off}"; }
die()  { echo "${c_err}✗ $*${c_off}" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' non trovato: $2"; }

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
  else head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

load_state() { [ -f "$STATE_FILE" ] && . "./$STATE_FILE" || true; }
save_state() {
  ( umask 077
    cat > "$STATE_FILE" <<EOS
WORKER_NAME='${WORKER_NAME}'
KV_ID='${KV_ID:-}'
ACCESS_TOKEN='${ACCESS_TOKEN:-}'
ADMIN_TOKEN='${ADMIN_TOKEN:-}'
WORKER_URL='${WORKER_URL:-}'
EOS
  )
}

check_prereqs() {
  need node "installa Node.js >= 18 (https://nodejs.org)"
  need npx  "installa npm (incluso in Node.js)"
  need curl "installa curl"
  local major; major=$(node -p 'process.versions.node.split(".")[0]')
  [ "$major" -ge 18 ] || die "serve Node.js >= 18 (trovato $(node -v))"
}

ensure_auth() {
  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then return; fi
  if ! $WR whoami 2>&1 | grep -qiE 'associated with the email|Account ID|You are logged in'; then
    log "Login a Cloudflare (si apre il browser)…"
    $WR login
  fi
}

ensure_kv() {
  local title="${WORKER_NAME}-kv" out
  if [ -z "${KV_ID:-}" ]; then
    out=$($WR kv namespace list 2>/dev/null || true)
    KV_ID=$(printf '%s' "$out" | node -e '
      let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
        try{const a=JSON.parse(s.slice(s.indexOf("[")));const t=process.argv[1];
        const m=a.find(x=>x.title===t);if(m)console.log(m.id)}catch{}})' "$title")
  fi
  if [ -z "${KV_ID:-}" ]; then
    log "Creo il namespace KV '$title'"
    out=$($WR kv namespace create "$title" 2>&1) || { echo "$out" >&2; die "creazione KV fallita"; }
    KV_ID=$(printf '%s' "$out" | grep -oE '[0-9a-f]{32}' | head -1)
    [ -n "$KV_ID" ] || { echo "$out" >&2; die "impossibile leggere l'id del KV"; }
  else
    warn "KV namespace già presente: $KV_ID"
  fi
  sed -i.bak -E "s/^(id = \")[^\"]*(\")/\1${KV_ID}\2/" wrangler.toml && rm -f wrangler.toml.bak
}

upload_lists() {
  [ -n "${KV_ID:-}" ] || die "KV_ID mancante: esegui prima ./setup.sh deploy"
  log "Compilo le blocklist in locale…"
  rm -rf build
  node tools/build-blocklist.mjs build
  log "Carico su Cloudflare KV…"
  $WR kv key put blocklist --path build/blocklist.bin --namespace-id "$KV_ID" --remote >/dev/null
  $WR kv key put meta --path build/meta.json --namespace-id "$KV_ID" --remote >/dev/null
  rm -rf build
}

cmd_deploy() {
  check_prereqs
  load_state
  [ -f package.json ] || die "esegui lo script dalla root del progetto"
  ensure_auth
  ensure_kv

  ACCESS_TOKEN="${ACCESS_TOKEN:-$(rand_hex 16)}"
  ADMIN_TOKEN="${ADMIN_TOKEN:-$(rand_hex 24)}"

  log "Deploy del worker '$WORKER_NAME'…"
  local args=(deploy --name "$WORKER_NAME")
  [ -n "${CUSTOM_DOMAIN:-}" ] && args+=(--domain "$CUSTOM_DOMAIN")
  local out; out=$($WR "${args[@]}" 2>&1 | tee /dev/stderr) || die "deploy fallito"

  if [ -n "${CUSTOM_DOMAIN:-}" ]; then WORKER_URL="https://$CUSTOM_DOMAIN"
  else
    WORKER_URL=$(printf '%s' "$out" | grep -oE 'https://[A-Za-z0-9.-]+\.workers\.dev' | head -1 || true)
    [ -n "$WORKER_URL" ] || read -rp "URL del worker (https://...): " WORKER_URL
  fi

  log "Imposto i secret (token di accesso e admin)…"
  local tmp; tmp=$(mktemp)
  printf '{"ACCESS_TOKENS":"%s","ADMIN_TOKEN":"%s"}' "$ACCESS_TOKEN" "$ADMIN_TOKEN" > "$tmp"
  $WR secret bulk "$tmp" --name "$WORKER_NAME" >/dev/null || { rm -f "$tmp"; die "impostazione secret fallita"; }
  rm -f "$tmp"
  save_state

  upload_lists
  cmd_info
}

cmd_info() {
  load_state
  [ -n "${WORKER_URL:-}" ] || die "worker non ancora configurato: ./setup.sh deploy"
  cat <<EOS

${c_ok}✔ Private DNS pronto${c_off}

  DoH URL:         ${WORKER_URL}/${ACCESS_TOKEN}/dns-query
  Profilo Apple:   ${WORKER_URL}/${ACCESS_TOKEN}/apple.mobileconfig   (iOS / macOS)
  Admin token:     ${ADMIN_TOKEN}
  (salvati in ${STATE_FILE}, non condividere questi URL: il token è la tua "password")

  Firefox:  Impostazioni → Privacy → DNS su HTTPS → Personalizzato → incolla il DoH URL
  Chrome:   Impostazioni → Privacy e sicurezza → Sicurezza → DNS sicuro → Personalizzato
  Windows 11: Impostazioni → Rete → DNS → "Crittografia DNS: solo crittografato (DNS su HTTPS)"
  Test:     curl -s '${WORKER_URL}/${ACCESS_TOKEN}/dns-query?dns=AAABAAABAAAAAAAAC2RvdWJsZWNsaWNrA25ldAAAAQAB' | xxd | head -3

EOS
}

api() { # api METHOD PATH [json-body]
  load_state
  [ -n "${WORKER_URL:-}" ] && [ -n "${ADMIN_TOKEN:-}" ] || die "worker non configurato: ./setup.sh deploy"
  local method="$1" path="$2"; shift 2
  local data=(); [ $# -gt 0 ] && data=(--data "$1")
  curl -fsS -X "$method" -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'content-type: application/json' \
    ${data[@]+"${data[@]}"} "${WORKER_URL}${path}"
  echo
}

rules_action() { # rules_action ACTION domains...
  local action="$1"; shift
  [ $# -gt 0 ] || die "specifica almeno un dominio"
  local domains; domains=$(printf '"%s",' "$@"); domains="[${domains%,}]"
  api POST /admin/rules "{\"action\":\"$action\",\"domains\":$domains}"
}

case "${1:-deploy}" in
  deploy)  cmd_deploy ;;
  lists)   check_prereqs; load_state; ensure_auth; upload_lists ;;
  update)  api POST /admin/update ;;
  block)   shift; rules_action block "$@" ;;
  allow)   shift; rules_action allow "$@" ;;
  unrule)  shift; rules_action remove "$@" ;;
  rules)   api GET /admin/rules ;;
  check)   [ -n "${2:-}" ] || die "uso: $0 check <dominio>"; api GET "/admin/check?domain=$2" ;;
  status)  api GET /admin/status ;;
  info)    cmd_info ;;
  -h|--help|help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "comando sconosciuto: $1 (prova --help)" ;;
esac
