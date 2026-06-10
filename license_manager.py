import os
import uuid
import hashlib
import logging
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

class LicenseManager:
    """Gestiona la validación del estado PRO de la aplicación."""
    
    def __init__(self, settings_manager: Any) -> None:
        """Inicializa el gestor de licencias vinculándolo al hardware actual.
        
        Args:
            settings_manager (Any): Instancia de SettingsManager para la persistencia local.
        """
        self.settings = settings_manager.settings
        self._hwid = str(uuid.getnode())

    def _hash_key(self, key: str) -> str:
        """Deriva un hash verificable combinando la licencia y el hardware ID.
        
        Args:
            key (str): Clave de licencia en texto plano.
            
        Returns:
            str: Hash SHA-256 en formato hexadecimal.
        """
        data = f"{key}:{self._hwid}".encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def is_pro_active(self) -> bool:
        """Verifica si la aplicación tiene una licencia PRO activa y válida.
        
        Returns:
            bool: True si la licencia es válida o si se usa el entorno de desarrollo.
        """
        stored_hash = self.settings.value("pro_license_hash", "")
        stored_key = self.settings.value("pro_license_key", "")
        
        if not stored_hash:
            return False
            
        # Validar dinámicamente usando la clave real guardada y el HWID actual
        # Nota futura: Considerar cambiar esto por verificación de firma asimétrica (JWT/Ed25519)
        expected_hash = self._hash_key(stored_key)
        return stored_hash == expected_hash or os.environ.get("CIPHER_DEV_PRO") == "1"

    def activate_license(self, key: str) -> bool:
        """Activa la licencia validándola contra la API de Lemon Squeezy.
        
        Args:
            key (str): Clave de licencia proporcionada por el usuario.
            
        Returns:
            bool: True si la activación es exitosa, False en caso contrario.
        """
        # 1. Bypass para desarrollo local
        if os.environ.get("CIPHER_DEV_PRO") == "1":
            self.settings.setValue("pro_license_hash", self._hash_key(key))
            self.settings.setValue("pro_license_key", key.strip())
            return True

        # 2. Validación en Producción con Lemon Squeezy
        if not HAS_REQUESTS:
            logging.error("Librería 'requests' no instalada. No se puede validar la licencia.")
            return False

        try:
            url = "https://api.lemonsqueezy.com/v1/licenses/validate"
            payload = {
                "license_key": key.strip(),
                "instance_name": self._hwid  # Registra este dispositivo específico
            }
            headers = {"Accept": "application/json"}
            
            # Timeout corto para no congelar la UI indefinidamente
            response = requests.post(url, data=payload, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                # Lemon Squeezy devuelve 'valid': true si la clave es correcta y está activa
                if data.get("valid") is True:
                    # Guardamos el hash derivado localmente para que funcione offline después
                    self.settings.setValue("pro_license_hash", self._hash_key(key))
                    self.settings.setValue("pro_license_key", key.strip())
                    logging.info(f"Licencia activada exitosamente en Lemon Squeezy para la instancia {self._hwid}")
                    return True
                else:
                    error_msg = data.get("error", "Clave inválida o expirada.")
                    logging.warning(f"Fallo al validar en Lemon Squeezy: {error_msg}")
                    return False
            else:
                logging.error(f"Error HTTP del servidor de licencias: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            logging.error("Timeout al contactar a Lemon Squeezy.")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Error de red al validar licencia: {e}")
            return False

    def deactivate_license(self) -> None:
        """Elimina la información de la licencia del almacenamiento local."""
        self.settings.remove("pro_license_hash")
        self.settings.remove("pro_license_key")