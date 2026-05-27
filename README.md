# Scanner_Web

Scanner unifié pour identifier des services web embarqués sur un réseau et tester leurs credentials par défaut. Approche **fingerprint-d'abord, auth-ciblée-ensuite** — pas de brute-force.

Deux modes d'utilisation cohabitent dans ce repo :
- **Scanner unifié** (`scan.py`) — recommandé, un seul point d'entrée qui détecte tous les services connus en une passe.
- **4 testers standalone** (`iLO-Tester/`, `InfoPrint-Tester/`, `XPort-Tester/`, `SATO-Tester/`) — les versions originales, chaque service dans son dossier, autonome. Toujours fonctionnels.

## Services supportés

| Service | Cible | Méthode d'auth | Path protégé |
|---|---|---|---|
| `iLO` | HP iLO | JSON POST (session token) | `/json/login_session` |
| `InfoPrint` | InfoPrint 6700 (Ricoh/Printronix) | HTTP Basic Auth | `/indexConf.html` |
| `XPort` | Lantronix XPort | HTTP Basic Auth | `/secure/ltx_conf.htm` |
| `SATO` | SATO CL4NX Plus (et compatibles WebConfig) | Form POST + cookie session | `/WebConfig/lua/auth.lua` |

## Architecture (scanner unifié)

```
Scanner_Web/
├── scan.py                # CLI : argparse + dispatch + rendu table
├── targets.py             # Expansion CIDR / range
├── runner.py              # Moteur de scan parallèle (ThreadPoolExecutor)
├── services/
│   ├── base.py            # Classe Service de base + helpers communs
│   ├── ilo.py             # 1 fichier = 1 service (~30 lignes)
│   ├── infoprint.py
│   ├── xport.py
│   └── sato.py
├── data/
│   ├── ilo.creds.example.json
│   ├── infoprint.creds.example.json
│   ├── xport.creds.example.json
│   └── sato.creds.example.json
├── requirements.txt
├── targets.txt            # (gitignored)
└── targets.example.txt
```

Chaque service est une petite classe Python qui hérite de `Service` et déclare ses **signatures regex**, son **path protégé**, et — si nécessaire — sa propre méthode `try_login()`. Le `Service` de base fournit déjà la détection standard (`GET /` + match patterns + fallback probe) et l'auth HTTP Basic par défaut — donc beaucoup de services ne nécessitent que la déclaration des constantes.

## Setup

```powershell
git clone https://github.com/Inatsuo/Scanner_Web.git
cd Scanner_Web

pip install -r requirements.txt

# Copier les creds d'exemple en creds réels (et adapter si besoin)
foreach ($svc in 'ilo','infoprint','xport','sato') {
    Copy-Item "data/$svc.creds.example.json" "data/$svc.creds.json"
}

# Créer targets.txt avec les IPs à scanner (voir format ci-dessous)
```

## Usage

```powershell
python scan.py targets.txt [options]
```

### Options

| Flag | Effet |
|---|---|
| `--check-auth` | Essaye les creds de `data/<service>.creds.json` quand un service est détecté |
| `--service ilo,sato` | Filtre les services à tester (défaut : tous) |
| `--workers N` | Threads parallèles (défaut : 30) |
| `--only-found` | N'affiche dans la table que les devices détectés |
| `--verbose` | Logs DEBUG (utilise `--workers 1` pour rester lisible) |

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
# Scan complet d'une /24, tous les services, essayer les creds, ne montrer que les hits
python scan.py targets.txt --check-auth --only-found

# Cibler uniquement SATO et XPort
python scan.py targets.txt --service sato,xport --check-auth

# Debug d'une IP isolée
python scan.py targets.txt --workers 1 --verbose
```

## Logique de détection

Chaque scan se fait en **deux phases distinctes** :

1. **Fingerprint** — `GET /` puis match regex sur le body et les headers contre des signatures propres au service (ex: `Lantronix`, `InfoPrint`, `Microplex emHTTPD`, `WebConfig`, etc.). Si la racine ne dit rien d'utile, fallback sur un path connu du service (pour XPort par exemple, un simple `401` sur `/secure/ltx_conf.htm` est lui-même un signal, parce que ce path est unique à Lantronix).

2. **Auth ciblée** — si le service est identifié **et** que `--check-auth` est posé, on essaie les creds avec la bonne méthode :
   - **Basic Auth** pour InfoPrint et XPort (`Authorization: Basic base64(user:pass)`)
   - **JSON POST** pour iLO (avec session token dans la réponse)
   - **Form POST + cookie** pour SATO (`pw=...&group=...`, header `X-Requested-With: XMLHttpRequest`, cookie `web=true`)

Le succès n'est pas juste un `200 OK` — on revérifie que la réponse contient une signature attendue (ou n'a pas de marqueur d'erreur pour SATO), pour éviter les faux positifs sur les devices qui renvoient 200 quoi qu'il arrive.

## Ajouter un nouveau service

1. Créer `services/<nom>.py` avec une classe qui hérite de `Service` :

   ```python
   import re
   from .base import Service

   class MyService(Service):
       name = "MyService"
       creds_filename = "myservice.creds.json"
       patterns = re.compile(r"signature1|signature2", re.IGNORECASE)
       config_path = "/admin/login"
       # Pour de l'auth non-standard, override try_login(self, base_url, session)
   ```

2. Créer `data/myservice.creds.example.json` avec les defaults vendor :

   ```json
   [{"username": "admin", "password": "admin"}]
   ```

3. L'enregistrer dans `services/__init__.py` :

   ```python
   from .myservice import MyService
   ALL_SERVICES = [..., MyService]
   ```

4. Copier l'example vers le réel : `cp data/myservice.creds.example.json data/myservice.creds.json`

Done — le service est dispo via `--service myservice` ou inclus dans les scans complets.

## Fichiers sensibles exclus

Le `.gitignore` empêche par construction :
- `**/targets.txt` — les vraies IPs scannées
- `**/data/creds.json` (ancien layout) et `data/*.creds.json` (nouveau layout) — les creds réels
- `__pycache__/`, `.claude/`, `*.zip`

Les `*.creds.example.json` committés contiennent les **defaults publics du vendor** (admin/admin pour iLO, root/empty pour InfoPrint et XPort, settings/0310 pour SATO) — ces valeurs sont documentées dans les manuels constructeur, ce ne sont pas des secrets.

## Anciens testers standalone

Les 4 dossiers `<Service>-Tester/` (avec leur propre `main.py`, `scanner.py`, `data/creds.json`) restent fonctionnels et autonomes. Utilité : tu peux extraire un dossier sans le reste du repo si tu veux juste un scanner mono-service. Sinon, le `scan.py` unifié à la racine est plus pratique pour la grande majorité des usages.
