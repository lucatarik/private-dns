# private-dns

Resolver **DNS-over-HTTPS privato** su Cloudflare Workers, con blocco di ads, tracker e malware
(stile Control D / NextDNS), veloce e senza server da gestire.

## Come funziona

- **Blocco in ~1 µs**: le blocklist (HaGeZi Pro, StevenBlack, AdGuard DNS: ~390k domini) sono compilate in un
  unico array ordinato di hash a 53 bit su KV. Ogni isolate lo carica una volta e cerca con ricerca binaria,
  controllando il dominio e tutti i suoi parent (`x.ads.example.com` → `ads.example.com`).
- **Anti CNAME-cloaking**: se un nome "first-party" punta via CNAME a un tracker, viene bloccato anche lui.
- **Cache in memoria con TTL scalati** + *serve-stale* (risponde subito e rinfresca in background) +
  coalescing delle richieste identiche.
- **Privacy**: nessun log, nessuna analytics. Verso l'upstream (Cloudflare 1.1.1.1, fallback Quad9) viene inviata una query
  ripulita: niente ECS, cookie o padding del client.
- **Accesso privato**: il token è nel path (`/<token>/dns-query`); token sbagliato → 404. API admin protetta da bearer token.
- Regole personalizzate (block/allow), la più specifica vince; auto-aggiornamento liste via Cron Trigger.

## Setup (un comando)

```bash
./setup.sh
```

Lo script: fa login a Cloudflare (o usa `CLOUDFLARE_API_TOKEN`), crea il KV, genera i token, fa il deploy,
imposta i secret, compila e carica le blocklist e ti stampa il tuo DoH URL:

```
https://private-dns.<tuo-account>.workers.dev/<token>/dns-query
```

Opzioni: `WORKER_NAME=mio-dns ./setup.sh`, `CUSTOM_DOMAIN=dns.example.com ./setup.sh` (dominio sulla tua zona Cloudflare).

## Gestione

```bash
./setup.sh block  tracker.example.com     # blocca (con sottodomini)
./setup.sh allow  falso-positivo.com      # whitelist
./setup.sh unrule falso-positivo.com      # rimuove la regola
./setup.sh check  ads.doubleclick.net     # è bloccato?
./setup.sh lists                          # riscarica e ricompila le blocklist (locale, funziona anche su piano Free)
./setup.sh status | rules | info
```

Le modifiche sono attive entro ~2 minuti su tutti i colo (subito su quello che risponde all'API).

## Client

| Client | Configurazione |
|---|---|
| iOS / macOS | apri `https://…/<token>/apple.mobileconfig` e installa il profilo |
| Windows 11 | Impostazioni → DNS → server DNS personalizzato + template DoH |
| Firefox / Chrome | DNS su HTTPS → personalizzato → DoH URL |
| Android | il "DNS privato" di sistema richiede DoT (non supportato dai Workers): usa Intra, Firefox o Chrome con il DoH URL |

## Configurazione (`wrangler.toml`)

- `BLOCK_MODE`: `null` (0.0.0.0 / ::, default), `nxdomain`, `refused`.
- `UPSTREAMS`: DoH upstream in ordine (es. `https://security.cloudflare-dns.com/dns-query`).
- `BLOCKLISTS`: URL delle liste (hosts, domini semplici o formato AdGuard `||dominio^`).
- Cron ogni 6h: la compilazione nel Worker richiede il piano Workers Paid; sul piano Free rimuovi `[triggers]` e usa `./setup.sh lists`.

## Sviluppo

```bash
npm test                  # test di parsing DNS, filtro, cache, cloaking, admin API
node tools/build-blocklist.mjs build
```

## API admin

`Authorization: Bearer <ADMIN_TOKEN>`: `GET /admin/status`, `GET /admin/check?domain=…`, `GET|POST /admin/rules`
(`{"action":"block|allow|remove","domains":[…]}`), `POST /admin/update`.
