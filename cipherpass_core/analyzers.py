import math
from typing import Tuple
from zxcvbn import zxcvbn

MIN_UNIQUE_RATIO: float = 0.30

def QT_TRANSLATE_NOOP(context, text):
    return text

class StrengthAnalyzer:
    """Analiza la fortaleza de contraseñas basándose en zxcvbn y entropía matemática."""
    
    @staticmethod
    def get_unified_metrics(password: str) -> Tuple[int, str, str, float, str]:
        if not password:
            return 0, "", "...", 0.0, ""

        results = zxcvbn(password)
        crack_seconds = float(results["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"])
        warning = results["feedback"]["warning"]

        if len(password) > 6:
            unique_chars = len(set(password))
            if (unique_chars / len(password)) < MIN_UNIQUE_RATIO:
                crack_seconds = min(crack_seconds, 60.0)
                warning = QT_TRANSLATE_NOOP("CipherPassApp", "Muchos caracteres repetidos")

        if crack_seconds < 86400:
            val, color, msg = 15, "#e74c3c", QT_TRANSLATE_NOOP("CipherPassApp", "Muy Débil")
        elif crack_seconds < 31536000:
            val, color, msg = 35, "#e67e22", QT_TRANSLATE_NOOP("CipherPassApp", "Débil")
        elif crack_seconds < 315360000:
            val, color, msg = 55, "#f1c40f", QT_TRANSLATE_NOOP("CipherPassApp", "Regular")
        elif crack_seconds < 3153600000:
            val, color, msg = 80, "#2ecc71", QT_TRANSLATE_NOOP("CipherPassApp", "Buena")
        else:
            val, color, msg = 100, "#3498db", QT_TRANSLATE_NOOP("CipherPassApp", "Muy Fuerte")

        return val, color, msg, crack_seconds, warning

    @staticmethod
    def calculate_entropy_preview(length: int, use_upper: bool, use_lower: bool, use_nums: bool, use_syms: bool) -> Tuple[int, str, str]:
        pool_size = 0
        if use_upper: pool_size += 26
        if use_lower: pool_size += 26
        if use_nums: pool_size += 10
        if use_syms: pool_size += 30

        if pool_size == 0 or length == 0:
            return 0, "#e74c3c", QT_TRANSLATE_NOOP("CipherPassApp", "Débil")

        entropy = length * math.log2(pool_size)
        val = min(95, int((entropy / 80.0) * 100))
        
        if entropy < 50:
            color, msg = "#e74c3c", QT_TRANSLATE_NOOP("CipherPassApp", "Débil")
        elif entropy < 75:
            color, msg = "#f39c12", QT_TRANSLATE_NOOP("CipherPassApp", "Moderada")
        else:
            color, msg = "#2ecc71", QT_TRANSLATE_NOOP("CipherPassApp", "Fuerte")

        return val, color, msg