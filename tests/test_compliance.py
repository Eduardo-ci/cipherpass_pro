import unittest
import os
import tempfile
from unittest.mock import patch

from main import ComplianceManager

class TestComplianceManager(unittest.TestCase):
    def setUp(self):
        # Limpiamos la caché del manager antes de cada prueba para forzar la lectura del disco
        ComplianceManager._PRESETS = None

    def test_load_presets_success(self):
        """Prueba que el archivo JSON real se pueda leer y el esquema se valide correctamente."""
        ComplianceManager._load_presets()
        self.assertIsNotNone(ComplianceManager._PRESETS)
        self.assertIn("NIST 800-63B", ComplianceManager._PRESETS)
        
        # Verifica que los tipos correspondan al schema exigido (bool, int)
        nist_rules = ComplianceManager.get_preset_rules("NIST 800-63B")
        self.assertIsInstance(nist_rules["length"], int)
        self.assertIsInstance(nist_rules["upper"], bool)

    @patch("main.resource_path")
    def test_load_presets_fallback_on_corrupt_file(self, mock_resource_path):
        """Prueba que el sistema no colapse ante un JSON inválido y use su Fallback seguro."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            # Inyectamos un string donde la UI esperaría un entero (violación de esquema)
            tmp.write('{"Fake Compliance": {"length": "veinte", "upper": true, "lower": true, "nums": true, "syms": true, "min_n": 1, "min_s": 1}}')
            tmp_path = tmp.name
            
        mock_resource_path.return_value = tmp_path
        
        ComplianceManager._load_presets()
        # A pesar de que el archivo era corrupto, el Fallback debió cargarse inyectando "AWS IAM"
        self.assertIn("AWS IAM", ComplianceManager._PRESETS)
        os.remove(tmp_path)