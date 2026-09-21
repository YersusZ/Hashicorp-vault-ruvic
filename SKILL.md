---
name: hashicorp-vault
description: >
  Usa la librería ruvic_hashicorp_vault_connector para leer y escribir secretos
  KV, renovar o revocar leases y pedir credenciales dinámicas (database, aws,
  azure, gcp, ssh) en HashiCorp Vault. Úsala cuando el usuario pida Vault,
  un secreto, rotar una credencial o un lease.
triggers:
- vault
- hashicorp
- secreto
- kv
- approle
- lease
---

# Conector HashiCorp Vault (ruvic_hashicorp_vault_connector)

Librería Python para la API HTTP de Vault. Está **preinstalada en el runtime** cuando el conector `hashicorp_vault` está configurado. Si no, instálala con `pip install git+https://github.com/YersusZ/Hashicorp-vault-ruvic.git#subdirectory=lib`.

El conector no crea mounts ni políticas. Usa los que ya existen.

## Regla crítica de credenciales

El código generado **NUNCA hardcodea** tokens, Role ID ni Secret ID. Se leen de estas variables (sin segmento de alias):

| Variable | Contenido |
|----------|-----------|
| `RUVIC_HASHICORP_VAULT_VAULT_URL` | URL del cluster |
| `RUVIC_HASHICORP_VAULT_AUTH_MODE` | `approle` o `token` |
| `RUVIC_HASHICORP_VAULT_ROLE_ID` | Role ID (AppRole) |
| `RUVIC_HASHICORP_VAULT_SECRET_ID` | Secret ID (AppRole) |
| `RUVIC_HASHICORP_VAULT_TOKEN` | Token (modo token) |
| `RUVIC_HASHICORP_VAULT_KV_MOUNT` | Mount KV (default `secret`) |
| `RUVIC_HASHICORP_VAULT_KV_VERSION` | `v2` o `v1` |
| `RUVIC_HASHICORP_VAULT_DATABASE_MOUNT` | Mount database |
| `RUVIC_HASHICORP_VAULT_AWS_MOUNT` | Mount AWS |
| `RUVIC_HASHICORP_VAULT_AZURE_MOUNT` | Mount Azure |
| `RUVIC_HASHICORP_VAULT_GCP_MOUNT` | Mount GCP |
| `RUVIC_HASHICORP_VAULT_SSH_MOUNT` | Mount SSH |

Si no existen, el conector no está configurado: no generes código que lo use; indica al usuario que lo configure en **Settings → Conectores**.

NUNCA uses nombres con alias (`_DEFAULT_`, `_PRODUCCION_`, etc.) salvo que aparezcan en la sección autogenerada «Variables en tu entorno» al final de este skill.

Nunca imprimas `TOKEN`, `SECRET_ID` ni el contenido de un secreto en logs.

## Conexión (siempre igual)

```python
from ruvic_hashicorp_vault_connector import VaultClient

client = VaultClient()
client.authenticate()
```

## Leer un secreto KV

```python
secret = client.kv_read("app/api")
print(secret["data"])
```

## Escribir o rotar un secreto KV

En KV v2, escribir crea una versión nueva.

```python
client.kv_write("app/api", {"username": "app", "password": "nuevo-valor"})
```

## Listar claves (sin valores)

```python
listed = client.kv_list("app")
print(listed["data"])
```

## Credencial dinámica de base de datos

```python
creds = client.generate_dynamic("database", "creds/readonly")
print(creds["data"]["username"])
print(creds["lease_id"])
```

## Renovar o revocar un lease

```python
client.lease_renew(creds["lease_id"])
client.lease_revoke(creds["lease_id"])
```

## Manejo de errores

```python
from ruvic_hashicorp_vault_connector import (
    VaultAuthError,
    VaultDataError,
    VaultNetworkError,
)

try:
    secret = client.kv_read("app/api")
except VaultAuthError:
    print("Credenciales inválidas — revisa Settings → Conectores")
except VaultNetworkError:
    print("No se pudo alcanzar Vault — revisa la URL y la red")
except VaultDataError as exc:
    print(f"Error de datos: {exc}")
```

## Buenas prácticas al generar código

1. Deja que `VaultClient()` lea `RUVIC_HASHICORP_VAULT_*`. No pases el token en el código.
2. No imprimas secretos ni leases completos si el usuario solo pidió comprobar que existen.
3. `lease_revoke` revoca un lease concreto. No revoques por prefijo.
4. Los engines dinámicos tienen que estar montados en Vault; si no, explica que falta el mount.
