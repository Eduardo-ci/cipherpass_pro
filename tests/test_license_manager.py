import unittest
import os
from unittest.mock import patch, MagicMock

from license_manager import LicenseManager, HAS_REQUESTS

class TestLicenseManager(unittest.TestCase):
    def setUp(self):
        # Simulamos SettingsManager y QSettings para no escribir en el disco real
        self.mock_settings_manager = MagicMock()
        self.mock_settings = MagicMock()
        self.mock_settings_manager.settings = self.mock_settings
        
        # Diccionario en memoria para simular el almacenamiento local
        self.storage = {}
        def set_value(k, v): self.storage[k] = v
        def get_value(k, default=""): return self.storage.get(k, default)
        def remove_value(k): self.storage.pop(k, None)
        
        self.mock_settings.setValue.side_effect = set_value
        self.mock_settings.value.side_effect = get_value
        self.mock_settings.remove.side_effect = remove_value

        # Inicializamos el gestor con nuestra configuración falsa
        self.manager = LicenseManager(self.mock_settings_manager)

    def test_hash_key_generation(self):
        """Prueba que la generación del hash sea determinista y correcta."""
        key = "TEST-LICENSE-KEY"
        hashed = self.manager._hash_key(key)
        self.assertEqual(len(hashed), 64, "El hash SHA-256 debe tener 64 caracteres.")
        self.assertIsInstance(hashed, str)

    @patch.dict(os.environ, {"CIPHER_DEV_PRO": "1"})
    def test_activate_license_dev_mode(self):
        """Prueba que el modo de desarrollo active la licencia sin llamar a la red."""
        key = "DEV-MODE-KEY"
        result = self.manager.activate_license(key)
        
        self.assertTrue(result, "La licencia debería activarse en modo desarrollador.")
        self.assertEqual(self.storage["pro_license_key"], key)
        self.assertEqual(self.storage["pro_license_hash"], self.manager._hash_key(key))

    @unittest.skipIf(not HAS_REQUESTS, "La librería requests no está instalada.")
    @patch('license_manager.requests.post')
    @patch.dict(os.environ, {}, clear=True)  # Nos aseguramos de que DEV_PRO no esté activo
    def test_activate_license_production_success(self, mock_post):
        """Prueba una activación exitosa simulando la respuesta de Lemon Squeezy."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": True}
        mock_post.return_value = mock_response

        key = "VALID-PROD-KEY"
        result = self.manager.activate_license(key)
        
        self.assertTrue(result)
        self.assertEqual(self.storage["pro_license_key"], key)
        mock_post.assert_called_once()

    @unittest.skipIf(not HAS_REQUESTS, "La librería requests no está instalada.")
    @patch('license_manager.requests.post')
    @patch.dict(os.environ, {}, clear=True)
    def test_activate_license_production_failure(self, mock_post):
        """Prueba una activación fallida (clave expirada o inválida)."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"valid": False, "error": "License expired"}
        mock_post.return_value = mock_response

        result = self.manager.activate_license("INVALID-KEY")
        
        self.assertFalse(result)
        self.assertNotIn("pro_license_key", self.storage, "No se debe guardar la clave si falla.")

    @patch.dict(os.environ, {}, clear=True)
    def test_is_pro_active_logic(self):
        """Prueba la validación local offline mediante hash vs HWID."""
        key = "MY-VALID-KEY"
        
        # Caso 1: Todo correcto
        self.storage["pro_license_key"] = key
        self.storage["pro_license_hash"] = self.manager._hash_key(key)
        self.assertTrue(self.manager.is_pro_active())
        
        # Caso 2: Licencia copiada de otra máquina (El hash no coincide con el HWID actual)
        self.storage["pro_license_hash"] = "FAKE-OR-COPIED-HASH"
        self.assertFalse(self.manager.is_pro_active(), "Debe fallar si el HWID no coincide con el Hash.")
        
        # Caso 3: Desactivar licencia (limpieza de memoria local)
        self.manager.deactivate_license()
        self.assertNotIn("pro_license_hash", self.storage)
        self.assertFalse(self.manager.is_pro_active())