# 🔐 CipherPass Core

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Security](https://img.shields.io/badge/security-AES--GCM%20%7C%20Argon2id-red)
![License](https://img.shields.io/badge/license-AGPL_3.0-blue)
![Dual License](https://img.shields.io/badge/license-Dual_Licensing-orange)

*Read this in other languages: English | Español*

---

## English

**CipherPass Core** is the underlying, open-source cryptographic engine that powers the **CipherPass PRO** desktop application. It provides a suite of tools for generating, analyzing, and protecting credentials with a strong focus on privacy (*offline-first*).

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

### 📦 CipherPass PRO (Desktop Application)

If you are looking for an elegant graphical interface, visual vault exports, QR code generation for TOTP, and compliance profiles, discover the desktop application powered by this engine on the official website of **CipherPass PRO**.

### 📄 License (Dual Licensing)

This project uses a **Dual Licensing** model to ensure that open-source remains free while protecting the work from unauthorized commercial uses:

1. **Open Source License (GNU AGPLv3):** You are free to audit, study, and use this source code in personal or open-source projects. However, if you integrate this core into a software or web service and distribute/offer it to the public, **you are obligated** to release your own source code under the same terms (AGPLv3).
2. **Commercial License:** If you represent a company and wish to use `cipherpass_core` in a closed-source proprietary software, commercial application, or SaaS product (and do not wish to publish your source code), please contact the developers to purchase a commercial license.

---

## Español

**CipherPass Core** es el motor criptográfico subyacente y de código abierto que impulsa la aplicación de escritorio **CipherPass PRO**. Proporciona una suite de herramientas de generación, análisis y protección de credenciales enfocadas en la privacidad (*offline-first*).

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

### 📦 CipherPass PRO (Aplicación de Escritorio)

Si buscas una interfaz gráfica elegante, exportación visual de bóvedas, lectura de códigos QR para TOTP y perfiles de cumplimiento normativo (Compliance), descubre la aplicación de escritorio impulsada por este motor en la web oficial de **CipherPass PRO**.

### 📄 Licencia (Dual Licensing)

Este proyecto utiliza un modelo de **Licencia Doble (Dual Licensing)** para garantizar que el código abierto siga siendo libre, mientras se protege el trabajo de usos comerciales privativos no autorizados:

1. **Licencia Open Source (GNU AGPLv3):** Eres libre de auditar, estudiar y utilizar este código fuente en proyectos personales o de código abierto. Sin embargo, si integras este núcleo en un software o servicio web y lo distribuyes/ofreces al público, **estás obligado** a liberar tu propio código fuente bajo los mismos términos (AGPLv3).
2. **Licencia Comercial:** Si representas a una empresa y deseas utilizar `cipherpass_core` en un software privativo cerrado, aplicación comercial, o producto SaaS (y no deseas publicar tu código fuente), por favor contacta a los desarrolladores para adquirir una licencia comercial.