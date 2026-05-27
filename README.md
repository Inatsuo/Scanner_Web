# Scanner_Web

Toolkit de 4 scanners légers pour identifier des services web embarqués sur un réseau et tester leurs credentials par défaut. Approche **fingerprint-d'abord, auth-ciblée-ensuite** — pas de brute-force.

## Services supportés

| Tester | Cible | Méthode d'auth | Path protégé |
|---|---|---|---|
| `iLO-Tester` | HP iLO | JSON POST (session token) | `/json/login_session` |
| `InfoPrint-Tester` | InfoPrint 6700 (Ricoh/Printronix) | HTTP Basic Auth | `/indexConf.html` |
| `XPort-Tester` | Lantronix XPort | HTTP Basic Auth | `/secure/ltx_conf.htm` |
| `SATO-Tester` | SATO CL4NX Plus (et compatibles WebConfig) | Form POST + cookie session | `/WebConfig/lua/auth.lua` |

## Structure

```
Scanner_Web/
├── iLO-Tester/
│   ├── main.py
│   ├── scanner.py
│   ├── requirements.txt
│   └── data/
│       └── creds.example.json
├── InfoPrint-Tester/   (même layout)
├── XPort-Tester/       (même layout)
├── SATO-Tester/        (même layout)
├── targets.example.txt
└── .gitignore
```

Chaque tester est **autonome** — pas de dépendance partagée entre dossiers, tu peux en extraire un et l'utiliser indépendamment.

## Setup

```powershell
git clone https://github.com/Inatsuo/Scanner_Web.git
cd Scanner_Web

# Pour chaque tester :
cd <Service>-Tester
pip install -r requirements.txt
cp data/creds.example.json data/creds.json
# crée targets.txt avec les IPs à scanner (voir format ci-dessous)
```

## Usage

```powershell
python main.py targets.txt [options]
```

### Options

| Flag | Effet |
|---|---|
| `--check-auth` | Essaye les creds de `data/creds.json` quand le service est détecté |
| `--workers N` | Threads parallèles (défaut: 30) |
| `--only-found` | N'affiche dans la table que les devices détectés |
| `--verbose` | Logs DEBUG (utilise `--workers 1` pour que ce soit lisible) |

### Format `targets.txt`

```
# Les lignes commençant par # sont ignorées
10.0.0.5                    # IP simple
10.0.0.0/24                 # CIDR
10.0.0.1-50                 # range court (dernier octet)
10.0.0.1-10.0.1.50          # range full (multi-subnet)
```

**Note** : pas de zéros devant les octets. `10.0.0.05` est rejeté par Python (CVE-2021-29921). Écris `10.0.0.5`.

### Exemples

```powershell
# Scan d'une /24, ne montrer que les hits, essayer les creds
python main.py targets.txt --check-auth --only-found

# Debug d'une IP isolée
python main.py targets.txt --verbose --workers 1
```

## Logique de détection

Chaque scanner fonctionne en **deux phases distinctes** :

1. **Fingerprint** — `GET /` puis match regex sur le body et les headers contre des signatures propres au service (ex: `Lantronix`, `InfoPrint`, `Microplex emHTTPD`, `WebConfig`, etc.). Si la racine ne dit rien d'utile, fallback sur un path connu du service (pour XPort par exemple, un simple `401` sur `/secure/ltx_conf.htm` est lui-même un signal, parce que ce path est unique à Lantronix).

2. **Auth ciblée** — si le service est identifié **et** que `--check-auth` est posé, on essaie les creds de `creds.json` avec la bonne méthode :
   - **Basic Auth** pour InfoPrint et XPort (`Authorization: Basic base64(user:pass)`)
   - **JSON POST** pour iLO (avec session token dans la réponse)
   - **Form POST + cookie** pour SATO (`pw=...&group=...`, header `X-Requested-With: XMLHttpRequest`, cookie `web=true`)

Le succès n'est pas juste un `200 OK` — on revérifie que la réponse contient une signature attendue (ou n'a pas de marqueur d'erreur pour SATO), pour éviter les faux positifs sur les devices qui renvoient 200 quoi qu'il arrive.

## Fichiers sensibles exclus

Le `.gitignore` empêche par construction :
- `**/targets.txt` — les vraies IPs scannées
- `**/data/creds.json` — les creds réels en production
- `__pycache__/`, `.claude/`, `*.zip`

Les `creds.example.json` committés contiennent les **defaults publics du vendor** (admin/admin pour iLO, root/empty pour InfoPrint et XPort, settings/0310 pour SATO) — ces valeurs sont documentées dans les manuels constructeur, ce ne sont pas des secrets.

## Étendre à un nouveau service

Pour ajouter un nouveau tester, copier un dossier existant et adapter trois choses dans `scanner.py` :
1. **Signatures** : la regex `_*_PATTERNS` (chaînes uniques au service)
2. **Path protégé** : la constante `_CONFIG_PATH` ou équivalent
3. **`_try_login`** : la méthode d'authentification (Basic / JSON / form / autre)

Le `main.py` peut rester quasi identique — il suffit d'ajuster le titre de la table et le champ booléen.
