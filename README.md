# 🔐 CipherPass 

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![PySide6](https://img.shields.io/badge/PySide6-GUI-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Security](https://img.shields.io/badge/security-AES--GCM%20%7C%20Argon2id-red)

*Read this in other languages: English | Español*

---

## English

**CipherPass** is a powerful and secure desktop application designed to generate, validate, and protect cryptographic credentials. Built with **Python** and **Qt (PySide6)**, it focuses on *offline-first* privacy, ensuring your data never leaves your device unless you decide to do so.

### ✨ Features

CipherPass offers a *Freemium* model where essential tools will always be free, with advanced options available for **CipherPass PRO** users.

#### 🟢 Free Tier
- **Password Generator:** Create secure passwords by adjusting length, numbers, symbols, and avoiding ambiguous characters.
- **Passphrases (Diceware):** Generate easy-to-remember yet mathematically secure passphrases using encrypted local dictionaries.
- **Username Generator:** Create aliases and emails with "tags" (e.g., `user+netflix@gmail.com`) to track spam.
- **Strength Analyzer:** Check the estimated crack time using the `zxcvbn` algorithm and entropy calculations.

#### ⭐ PRO Tier (Premium)
- **HIBP Verification (Have I Been Pwned):** Validate if your password has been exposed in data breaches using *k-Anonymity* (only the SHA-1 prefix is sent, never your password).
- **Exportable Encrypted Vault:** Encrypt and export notes or JSONs using **AES-GCM** and key derivation with **Argon2id** (or PBKDF2).
- **TOTP Generator (2FA):** Create Base32 secrets and generate QR codes compatible with Google Authenticator or Authy.
- **Compliance Profiles:** Enforce password generation under strict regulations like **Active Directory, AWS IAM, PCI-DSS, or NIST 800-63B**.
- **API & Cloud Tokens:** Generate Hexadecimal strings, URL-Safe tokens, Bearer Tokens, and native UUIDv4.

---

### 🛡️ Security and Cryptography

Security is the pillar of CipherPass. This project implements industry standards:

- **Encryption at rest (Vault):** `AES-GCM` (Authenticated encryption) ensuring confidentiality and integrity.
- **Key Derivation (KDF):** Uses `Argon2id` (configured to consume 256MB of RAM to prevent GPU attacks) and `PBKDF2-SHA256` as a fallback.
- **Entropy Generation:** Uses `secrets.SystemRandom()` (OS CSPRNG), never predictable pseudo-random generators like `random`.
- **Memory Sanitization:** Explicit destruction (`del`) of master passwords and keys in memory immediately after use.
- **Diceware Database:** Word dictionaries are locally encrypted using symmetric `Fernet`.

---

### 🚀 Installation

#### Option 1: Install via `.deb` package (Debian/Ubuntu)
If you are on Linux, you can install the natively compiled application directly:

```bash
# Download the package (replace with the current version)
wget https://github.com/tu-usuario/CipherPass_Pro/releases/download/v1.0.3/cipherpass_1.0.3_amd64.deb

# Install the package
sudo dpkg -i cipherpass_1.0.3_amd64.deb

# If dependencies are missing, run:
sudo apt-get install -f
```
*Una vez instalada, búscalo en tu menú de aplicaciones o ejecuta `cipherpass` en la terminal.*

### Opción 2: Ejecutar desde el código fuente
Requiere Python 3.10+.

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/CipherPass_Pro.git
   cd CipherPass_Pro
   ```
2. Crea un entorno virtual y actívalo:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # En Linux/Mac
   # .venv\Scripts\activate   # En Windows
   ```
3. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   # Nota: Asegúrate de tener PySide6, zxcvbn, cryptography, argon2-cffi, qrcode, requests
   ```
4. Ejecuta la aplicación:
   ```bash
   python main.py
   ```

---

## 📦 Compilación de Binarios (Nuitka)

El proyecto incluye un script automatizado `build_package.sh` que traduce el código Python a **C nativo** usando Nuitka, empaquetándolo luego en un archivo `.deb` listo para distribución.

Para compilar:
```bash
chmod +x build_package.sh
./build_package.sh
```
*Esto requiere `build-essential`, `dpkg-deb` y `patchelf` en el sistema huésped.*

---

## 💻 Interfaz de Línea de Comandos (CLI)

CipherPass incluye una herramienta de terminal (`cipherpass_cli.py`) ideal para **SysAdmins, DevOps y automatización de pipelines (CI/CD)**. Permite generar credenciales, validar seguridad y cifrar secretos directamente desde la consola, pudiendo enlazarse con otras herramientas mediante la entrada estándar (`stdin`).

**Ejemplos de uso:**
```bash
# Generar una contraseña de 24 caracteres evitando ambiguos
python cipherpass_cli.py generate --length 24 --avoid-ambiguous

# Generar un secreto TOTP
python cipherpass_cli.py totp

# Comprobar si una contraseña está comprometida
python cipherpass_cli.py hibp "mi_contraseña_secreta"

# Cifrar el contenido de un archivo directamente hacia la bóveda (PRO)
cat secreto.txt | python cipherpass_cli.py vault-export - --argon2

# Descifrar contenido (PRO)
cat boveda.cpv | python cipherpass_cli.py vault-import -
```

---

## � Activación PRO

Puedes activar las funcionalidades PRO adquiriendo una clave de licencia. 
1. Ve a la pestaña **⭐ Pro** dentro de la app.
2. Ingresa tu clave de licencia proporcionada tras la compra.
3. Haz clic en **Activar**. 

*La licencia se vincula criptográficamente a tu Hardware ID (`uuid.getnode()`). Puedes revocarla y desactivarla localmente para transferirla a otro equipo.*

---

## 🤝 Contribución
¡Las contribuciones son bienvenidas! Si deseas reportar un error, solicitar una característica o enviar un *pull request*, siéntete libre de utilizar el gestor de Issues.

## 📄 Licencia
**CipherPass PRO** es software de código cerrado (Propietario) bajo un modelo Freemium. 

El uso de esta aplicación está regido por nuestro **Acuerdo de Licencia de Usuario Final (EULA)**, que prohíbe la distribución no autorizada, reventa, o ingeniería inversa del software y su sistema de licencias. Puedes leer los términos completos en el archivo `LICENSE` incluido en este repositorio.

*Nota: El motor criptográfico subyacente (`cipherpass_core`) es de código abierto y está disponible de manera pública bajo sus propios términos de licencia (Dual Licensing).*