import hashlib
import logging
from typing import Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def QT_TRANSLATE_NOOP(context, text):
    return text

class HIBPClient:
    """Cliente para interactuar con la API de Have I Been Pwned usando K-Anonymity."""
    
    @staticmethod
    def check_password(password: str) -> Tuple[int, str]:
        """Consulta la contraseña en HIBP de forma anónima."""
        if not HAS_REQUESTS:
            return -1, QT_TRANSLATE_NOOP("CipherPassApp", "La librería 'requests' no está instalada.")
            
        # SHA-1 is required by the HIBP k-anonymity API protocol.
        # This is NOT used for password storage or integrity — only for API lookup.
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()  # nosec B324
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {"User-Agent": "CipherPass Desktop App"}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                count = next((int(count) for h, count in hashes if h == suffix), 0)
                return count, ""
            else:
                error_prefix = QT_TRANSLATE_NOOP("CipherPassApp", "Error HTTP")
                return -1, f"{error_prefix} {response.status_code}"
        except Exception as e:
            logging.error(f"Fallo de red HIBP: {e}")
            return -1, QT_TRANSLATE_NOOP("CipherPassApp", "Error de conexión o timeout.")
        finally:
            del password
            del sha1_hash