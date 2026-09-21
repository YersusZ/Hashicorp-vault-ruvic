# HashiCorp Vault — conector Ruvic

Librería Python para que el agente de OpenHands gestione el **ciclo de vida de credenciales** en [HashiCorp Vault](https://developer.hashicorp.com/vault): secretos KV, credenciales dinámicas (AWS, Azure, GCP, base de datos, SSH) y leases.

El conector **no guarda secretos**. Lee `RUVIC_HASHICORP_VAULT_*` del entorno, llama a la API HTTP de Vault (`/v1/...`) y devuelve JSON.

Guía de producto (ES/EN): [`docs/index.html`](docs/index.html).

## OpenHands / Settings → Conectores

```text
lib/                          ruvic_hashicorp_vault_connector
manifest.json                 formulario (id: hashicorp_vault)
SKILL.md                      manual para el agente
test_connection.py            botón Probar conexión
docs/assets/icon.svg          icono del catálogo
```

Instalación de la librería (Python 3.10+):

```bash
pip install git+https://github.com/YersusZ/Hashicorp-vault-ruvic.git#subdirectory=lib
```

Prueba local, sin plataforma:

```bash
export RUVIC_HASHICORP_VAULT_VAULT_URL=http://127.0.0.1:8200
export RUVIC_HASHICORP_VAULT_AUTH_MODE=token
export RUVIC_HASHICORP_VAULT_TOKEN=...
python test_connection.py
python -m unittest tests/test_python_connector.py
```

En OpenHands la URL de este repo va en `ruvic_config/connector-requirements.txt`. El sync copia manifest, skill, test y docs; pip instala `lib/`.

## Nodo n8n

El directorio `nodes/` sigue siendo el nodo n8n (AppRole o token en la credencial **HashiCorp Vault API**). No lo usa Settings de OpenHands.

## Requisitos

- Node.js 18.10+
- Un cluster Vault accesible por HTTPS (en lab, el compose de este repo)
- AppRole (recomendado) o un token no-root

## Arranque rápido

```bash
npm install
cp .env.example .env
npm run build
```

Credencial en Ruvic: **HashiCorp Vault API**.

| Campo | Uso |
| --- | --- |
| Vault URL | `https://vault.ejemplo.com:8200` |
| Authentication | AppRole o Token |
| Namespace | Vault Enterprise; vacío en OSS |
| KV / AWS / Azure / GCP / Database / SSH Mount | Paths donde ya están montados los engines |

TLS permanece activo. `Ignore SSL issues` solo para laboratorios.

## Operaciones

| Recurso | Operaciones |
| --- | --- |
| **KV** | Read, Write, Rotate (nueva versión), Patch, List, Delete, Undelete, Destroy, metadata |
| **Lease** | Lookup, Renew, Revoke sincrónico (sin `revoke-force` / `revoke-prefix`) |
| **Database** | Generate credentials, static credentials, Rotate role, Rotate root |
| **SSH** | OTP, Sign certificate, Issue key |
| **AWS** | IAM, STS, Rotate root |
| **Azure** | Credentials, static credentials, Rotate role, Rotate root |
| **GCP** | Access token, service account key, Rotate root / roleset / roleset key |
| **System** | Health, Lookup self (el id del token se recorta) |

**Mask secret values** viene activo: passwords y tokens salen como `********` en el output.

KV no rota por sí mismo: Rotate escribe una versión nueva. Los motores dinámicos sí tienen `rotate-root` / `rotate-role`.

El conector **usa** mounts y políticas que ya existen en Vault; no los crea.

## Desarrollo y pruebas

```bash
npm test                 # unitarias (sin Vault)
npm run lint
```

Integración contra Vault local (KV + health):

```bash
systemctl --user start docker-desktop   # si usas Docker Desktop
docker compose -f docker-compose.vault.yml up -d
npm run test:integration
```

El compose publica Vault en `http://127.0.0.1:8200` con token `root` (solo lab). Variables en `.env` / `.env.example`. `npm test` no pega a Vault (`VAULT_INTEGRATION=false`).

Database, SSH y cloud requieren engines montados en el cluster; `vault -dev` vacío no los trae.

Documentación del portal:

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install "/ruta/a/ruvic-documentation/packages/ruvic-docs-check"
ruvic-docs-check
```

El paquete `ruvic-docs-check` vive en el repo privado `Robin-AI-Solutions/ruvic-documentation`. Si el clone por HTTPS falla, instálalo desde una copia local.

## Estructura

```text
lib/                 Librería Python del conector OpenHands
manifest.json        Formulario Settings (hashicorp_vault)
SKILL.md             Ejemplos para el agente
test_connection.py   Probar conexión
credentials/         Credencial n8n AppRole / Token
nodes/               Nodo n8n
docs/                Guía bilingüe del portal Ruvic
tests/               Unitarias Python + n8n
docker-compose.vault.yml
```
