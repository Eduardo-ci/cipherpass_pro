import json
import base64
import secrets
import hashlib
import logging
from typing import Optional

try:
    import argon2
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class VaultExporter:
    """Implementa cifrado fuerte aislado para la bóveda."""
    def __init__(self):
        self.secure_rng = secrets.SystemRandom()

    def _derive_key(self, password: str, salt: bytes, use_argon2: bool, params: dict = None) -> bytes:
        if params is None:
            params = {}
            
        if use_argon2 and HAS_ARGON2:
            # Extraer clave de 32 bytes pura saltando codificación PHC
            return argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=params.get("time_cost", 3), 
                memory_cost=params.get("memory_cost", 65536), 
                parallelism=params.get("parallelism", 4), 
                hash_len=32,
                type=argon2.low_level.Type.ID
            )
        else:
            return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, params.get("iterations", 600000), 32)

    def export_vault(self, data: str, master_password: str, use_argon2: bool) -> str:
        """Cifra los datos proporcionados usando un esquema AEAD y la contraseña maestra."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        try:
            # Aumentamos agresivamente los costos para resistir fuerza bruta offline
            if use_argon2 and HAS_ARGON2:
                kdf_params = {"time_cost": 5, "memory_cost": 262144, "parallelism": 4} # 256MB RAM
            else:
                kdf_params = {"iterations": 1000000} # 1 Millón iteraciones

            key = self._derive_key(master_password, salt, use_argon2, kdf_params)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
            
            payload = {
                "kdf": "argon2id" if (use_argon2 and HAS_ARGON2) else "pbkdf2-sha256",
                "kdf_params": kdf_params,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }
            return json.dumps(payload)
        except Exception as e:
            logging.error(f"Fallo al cifrar bóveda: {e}")
            raise
        finally:
            if 'key' in locals(): del key
            del master_password

    def import_vault(self, encrypted_json: str, master_password: str) -> Optional[str]:
        """Descifra una bóveda exportada usando la contraseña maestra."""
        try:
            payload = json.loads(encrypted_json)
            salt = base64.b64decode(payload["salt"])
            nonce = base64.b64decode(payload["nonce"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            use_argon2 = payload["kdf"] == "argon2id"
            kdf_params = payload.get("kdf_params", {}) # Extrae los parámetros guardados, o asume los antiguos por defecto
            
            key = self._derive_key(master_password, salt, use_argon2, kdf_params)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logging.warning(f"Fallo al descifrar bóveda: {e}")
            return None
        finally:
            if 'key' in locals(): del key
            del master_password