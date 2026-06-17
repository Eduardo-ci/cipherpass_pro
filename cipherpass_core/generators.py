import os
import string
import secrets
import logging
import uuid
import base64
from typing import List

from zxcvbn import zxcvbn

ZXCVBN_MIN_SCORE: int = 4
MAX_GENERATION_ATTEMPTS: int = 5
DEFAULT_SYMBOLS: str = "!@#$%^&*()-=_+[]{}|;:',.<>?/~`"

class PasswordEngine:
    """Provee métodos criptográficamente seguros para generación de credenciales."""
    
    def __init__(self, cipher_suite=None) -> None:
        self.diceware_words: List[str] = []
        self.cipher_suite = cipher_suite
        self.secure_rng = secrets.SystemRandom()

    def load_diceware(self, filepath: str) -> None:
        self.diceware_words = []
        if not os.path.exists(filepath):
            logging.warning(f"Archivo diceware no encontrado: {filepath}")
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            self.diceware_words = [w.strip() for w in content.split("\n") if w.strip()]
        except Exception as e:
            logging.error(f"Error cargando Diceware: {e}")

    def generate_password(self, length: int, min_nums: int, min_specs: int, 
                          use_upper: bool, use_lower: bool, use_nums: bool, 
                          use_syms: bool, avoid_amb: bool) -> str:
        """Genera una contraseña criptográficamente segura basada en restricciones."""
        chars = ""
        if use_upper: chars += string.ascii_uppercase
        if use_lower: chars += string.ascii_lowercase
        if use_nums: chars += string.digits
        if use_syms: chars += DEFAULT_SYMBOLS
        
        if not chars:
            return ""

        if avoid_amb:
            for bad in "l1I0O":
                chars = chars.replace(bad, "")

        best_candidate = ""
        best_score = -1

        for _ in range(MAX_GENERATION_ATTEMPTS):
            pwd: List[str] = []
            if use_nums:
                pwd.extend(secrets.choice(string.digits) for _ in range(min_nums))
            if use_syms:
                pwd.extend(secrets.choice(DEFAULT_SYMBOLS) for _ in range(min_specs))
            
            while len(pwd) < length:
                pwd.append(secrets.choice(chars))
            
            self.secure_rng.shuffle(pwd)
            candidate = "".join(pwd[:length])

            # SEGURIDAD (M-04): Verificar explícitamente que el candidato cumple
            # los mínimos requeridos después del shuffle y el slice. El shuffle
            # podría mover los caracteres obligatorios fuera del slice [:length]
            # si la lista tuviera más elementos que length.
            actual_nums = sum(1 for c in candidate if c in string.digits)
            actual_syms = sum(1 for c in candidate if c in DEFAULT_SYMBOLS)
            if use_nums and actual_nums < min_nums:
                continue
            if use_syms and actual_syms < min_specs:
                continue

            score = zxcvbn(candidate)["score"]
            if score >= ZXCVBN_MIN_SCORE:
                return candidate
            
            if score > best_score:
                best_score = score
                best_candidate = candidate

        return best_candidate

    def generate_passphrase(self, num_words: int, capitalize: bool, add_number: bool, separator: str) -> str:
        """Genera una frase de contraseña basada en listas de palabras (Diceware)."""
        if not self.diceware_words:
            return ""
        words = [secrets.choice(self.diceware_words) for _ in range(num_words)]
        if capitalize:
            words = [w.capitalize() for w in words]
        if add_number:
            idx = secrets.randbelow(len(words))
            words[idx] += str(secrets.randbelow(10))
        return separator.join(words)

    def generate_random_word(self) -> str:
        if self.diceware_words:
            return secrets.choice(self.diceware_words).lower()
        return "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))

    def generate_username(self, mode: int, domain: str, service: str, use_service: bool) -> str:
        base = self.generate_random_word()
        if mode == 0: return base
        if mode == 1:
            dom = domain.strip() or "gmail.com"
            if not dom.startswith("@"): dom = "@" + dom
            tag = f"+{service.strip()}" if use_service and service.strip() else ""
            return f"{base}{tag}{secrets.token_hex(2)}{dom}".lower()
        fmt = secrets.choice([f"{base}_{self.generate_random_word()}", f"{base}.{self.generate_random_word()}", f"{base}{secrets.randbelow(900) + 100}"])
        return fmt.lower()

    def generate_api_token(self, mode: int, length: int) -> str:
        """Genera un token seguro para APIs o un UUID v4."""
        if mode == 0: return secrets.token_urlsafe(length)
        if mode == 1: return secrets.token_hex(length)
        if mode == 2: return str(uuid.uuid4())
        if mode == 3: return "Bearer " + secrets.token_urlsafe(length)
        return ""

class TOTPEngine:
    """Provee secretos Base32 y generación de URI para 2FA."""
    
    @staticmethod
    def generate_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode('utf-8').replace('=', '')

    @staticmethod
    def build_uri(secret: str, account_name: str, issuer: str = "CipherPass") -> str:
        return f"otpauth://totp/{issuer}:{account_name}?secret={secret}&issuer={issuer}"