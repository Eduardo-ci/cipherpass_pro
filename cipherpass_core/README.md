# 🔐 CipherPass Core

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Security](https://img.shields.io/badge/security-AES--GCM%20%7C%20Argon2id-red)
![License](https://img.shields.io/badge/license-AGPL_3.0-blue)

*Read this in other languages: English | Español*

---

## English

**CipherPass Core** is the underlying cryptographic engine that powers the open-source **CipherPass** desktop application. It provides a suite of tools for generating, analyzing, and protecting credentials with a strong focus on privacy (*offline-first*).

By maintaining this core as open-source, we guarantee full transparency in the algorithms and methods used to handle the most sensitive data.

### ✨ Key Features

- **Password Generation (`PasswordEngine`):** Secure passwords, Diceware passphrases, and tokens (API/Cloud/UUID) using CSPRNG (`secrets.SystemRandom`).
- **Strength Analysis (`StrengthAnalyzer`):** Evaluation of estimated crack time based on `zxcvbn` and mathematical entropy calculations.
- **Secure HIBP Verification (`HIBPClient`):** Checking exposed passwords using the *k-Anonymity* model (sending only the first 5 characters of the SHA-1 hash).
- **Cryptographic Vault (`VaultExporter`):** Encryption at rest using **AES-GCM** and robust key derivation with **Argon2id** (or PBKDF2 as fallback).
- **TOTP Support (`TOTPEngine`):** Generation of Base32 secrets and URIs for Two-Factor Authentication (2FA) applications.

### 🚀 Installation

You can integrate `cipherpass_core` into your own Python projects:

```bash
git clone https://github.com/tu-usuario/cipherpass-core.git
cd cipherpass-core
pip install -r requirements.txt
```

*Main dependencies: `cryptography`, `zxcvbn`, `argon2-cffi`, `requests`.*

### 💻 Usage Example

```python
from cipherpass_core.generators import PasswordEngine
from cipherpass_core.analyzers import StrengthAnalyzer
from cipherpass_core.hibp import HIBPClient

# Generate a secure password
engine = PasswordEngine()
pwd = engine.generate_password(length=20, use_syms=True, avoid_amb=True)
print(f"Password: {pwd}")

# Analyze strength
metrics = StrengthAnalyzer.get_unified_metrics(pwd)
print(f"Strength: {metrics} - Estimated crack time: {metrics} seconds")

# Check if exposed anonymously
count, error = HIBPClient.check_password(pwd)
print(f"Times exposed: {count}")
```

### 🛡️ Security Architecture

This module is designed to ensure the least possible exposure of secrets:
- No predictable pseudo-random number generators (`random`) are used.
- Passwords are never sent in plaintext to any external server.
- Explicit memory sanitization after critical operations is facilitated.

### 📦 CipherPass (Desktop Application)

If you are looking for an elegant graphical interface, visual vault exports, QR code generation for TOTP, and compliance profiles, discover the desktop application powered by this engine on the official website of **CipherPass PRO**.

### 📄 License

This project is licensed under the **GNU AGPLv3**. You are free to audit, study, and use this source code. If you integrate this core into a software or web service and distribute/offer it to the public, **you are obligated** to release your own source code under the same terms (AGPLv3).

---

## Español

**CipherPass Core** es el motor criptográfico subyacente que impulsa la aplicación libre de escritorio **CipherPass**. Proporciona una suite de herramientas de generación, análisis y protección de credenciales enfocadas en la privacidad (*offline-first*).

Al mantener este núcleo como código abierto, garantizamos total transparencia en los algoritmos y métodos utilizados para manejar los datos más sensibles.

### ✨ Características Principales

- **Generación de Contraseñas (`PasswordEngine`):** Contraseñas seguras, frases Diceware y tokens (API/Cloud/UUID) usando CSPRNG (`secrets.SystemRandom`).
- **Análisis de Fortaleza (`StrengthAnalyzer`):** Evaluación de tiempo de descifrado basada en `zxcvbn` y cálculos matemáticos de entropía.
- **Verificación HIBP Segura (`HIBPClient`):** Consulta de contraseñas filtradas utilizando el modelo *k-Anonymity* (envío solo de los primeros 5 caracteres del hash SHA-1).
- **Bóveda Criptográfica (`VaultExporter`):** Cifrado en reposo utilizando **AES-GCM** y derivación de claves robusta con **Argon2id** (o PBKDF2 como respaldo).
- **Soporte TOTP (`TOTPEngine`):** Generación de secretos Base32 y URIs para aplicaciones de autenticación de dos factores (2FA).

### 🚀 Instalación

Puedes integrar `cipherpass_core` en tus propios proyectos Python:

```bash
git clone https://github.com/tu-usuario/cipherpass-core.git
cd cipherpass-core
pip install -r requirements.txt
```

*Dependencias principales: `cryptography`, `zxcvbn`, `argon2-cffi`, `requests`.*

### 💻 Ejemplo de Uso

```python
from cipherpass_core.generators import PasswordEngine
from cipherpass_core.analyzers import StrengthAnalyzer
from cipherpass_core.hibp import HIBPClient

# Generar una contraseña segura
engine = PasswordEngine()
pwd = engine.generate_password(length=20, use_syms=True, avoid_amb=True)
print(f"Contraseña: {pwd}")

# Analizar fortaleza
metrics = StrengthAnalyzer.get_unified_metrics(pwd)
print(f"Fortaleza: {metrics} - Tiempo estimado de crackeo: {metrics} segundos")

# Comprobar si ha sido expuesta de forma anónima
count, error = HIBPClient.check_password(pwd)
print(f"Veces expuesta: {count}")
```

### 🛡️ Arquitectura de Seguridad

Este módulo está diseñado para que los secretos tengan la menor exposición posible:
- No se utilizan generadores pseudoaleatorios predecibles (`random`).
- No se envían contraseñas en texto plano a ningún servidor externo.
- Se facilita el saneamiento de memoria tras operaciones críticas.

### 📦 CipherPass (Aplicación de Escritorio)

Si buscas una interfaz gráfica elegante, exportación visual de bóvedas, lectura de códigos QR para TOTP y perfiles de cumplimiento normativo (Compliance), descubre la aplicación de escritorio en este mismo repositorio.

### 📄 Licencia

Este proyecto está liberado bajo la licencia **GNU AGPLv3**. Eres libre de auditar, estudiar y utilizar este código fuente. Si integras este núcleo en un software o servicio web y lo distribuyes/ofreces al público, **estás obligado** a liberar tu propio código fuente bajo los mismos términos (AGPLv3).