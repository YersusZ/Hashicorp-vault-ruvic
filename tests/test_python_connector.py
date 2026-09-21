"""Pruebas locales de la librería Python, sin cluster Vault."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))

from ruvic_hashicorp_vault_connector import VaultClient, VaultConfig, VaultDataError
from ruvic_hashicorp_vault_connector.paths import sanitize_path

_PREFIX = 'RUVIC_HASHICORP_VAULT_'


class VaultConnectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._previous = {
            key: value
            for key, value in os.environ.items()
            if key.startswith(_PREFIX)
        }
        for key in list(self._previous):
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        for key in list(os.environ):
            if key.startswith(_PREFIX):
                os.environ.pop(key, None)
        os.environ.update(self._previous)

    def test_rejects_parent_path(self) -> None:
        with self.assertRaises(VaultDataError):
            sanitize_path('../secret')

    def test_missing_url_names_settings(self) -> None:
        os.environ[f'{_PREFIX}AUTH_MODE'] = 'token'
        os.environ[f'{_PREFIX}TOKEN'] = 'test-token'
        with self.assertRaises(ValueError) as raised:
            VaultConfig.from_env()
        self.assertIn('Settings → Conectores', str(raised.exception))

    def test_kv_read_uses_v2_data_path(self) -> None:
        os.environ[f'{_PREFIX}VAULT_URL'] = 'https://vault.example'
        os.environ[f'{_PREFIX}AUTH_MODE'] = 'token'
        os.environ[f'{_PREFIX}TOKEN'] = 'test-token'
        os.environ[f'{_PREFIX}KV_VERSION'] = 'v2'
        seen: list[tuple[str, str]] = []

        def transport(method, path, query, body, authenticated, allow_statuses):
            seen.append((method, path))
            return {'data': {'data': {'user': 'app'}, 'metadata': {'version': 2}}}

        client = VaultClient(transport=transport)
        result = client.kv_read('app/api')
        self.assertEqual(result['data'], {'user': 'app'})
        self.assertEqual(seen, [('GET', 'secret/data/app/api')])

    def test_approle_login_keeps_token_out_of_return_value(self) -> None:
        os.environ[f'{_PREFIX}VAULT_URL'] = 'https://vault.example'
        os.environ[f'{_PREFIX}AUTH_MODE'] = 'approle'
        os.environ[f'{_PREFIX}ROLE_ID'] = 'role'
        os.environ[f'{_PREFIX}SECRET_ID'] = 'secret'

        def transport(method, path, query, body, authenticated, allow_statuses):
            self.assertEqual(path, 'auth/approle/login')
            self.assertFalse(authenticated)
            self.assertNotIn('client_token', str(path))
            return {'auth': {'client_token': 's.hidden', 'renewable': True}}

        client = VaultClient(transport=transport)
        client.authenticate()
        self.assertEqual(client._token, 's.hidden')


if __name__ == '__main__':
    unittest.main()
