# 🔐 CipherPass 

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![PySide6](https://img.shields.io/badge/PySide6-GUI-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Security](https://img.shields.io/badge/security-AES--GCM%20%7C%20Argon2id-red)

**CipherPass** es una potente y segura aplicación de escritorio diseñada para generar, validar y proteger credenciales criptográficas. Construida con **Python** y **Qt (PySide6)**, se enfoca en la privacidad *offline-first*, garantizando que tus datos nunca abandonen tu dispositivo a menos que tú lo decidas.

---

## ✨ Características

CipherPass ofrece un modelo *Freemium* donde las herramientas esenciales siempre serán gratuitas, con opciones avanzadas disponibles para usuarios de **CipherPass PRO**.

### 🟢 Versión Free (Gratuita)
- **Generador de Contraseñas:** Crea contraseñas seguras ajustando longitud, números, símbolos y evitando caracteres ambiguos.
- **Frases de Contraseña (Diceware):** Genera frases fáciles de recordar pero matemáticamente seguras usando diccionarios locales cifrados.
- **Generador de Usuarios:** Crea alias y correos electrónicos con "tags" (ej. `user+netflix@gmail.com`) para rastrear el spam.
- **Analizador de Fortaleza:** Comprueba el tiempo estimado de descifrado (*crack time*) utilizando el algoritmo `zxcvbn` y cálculos de entropía.

### ⭐ Versión PRO (Premium)
- **Verificación HIBP (Have I Been Pwned):** Valida si tu contraseña ha sido expuesta en filtraciones de datos usando *k-Anonymity* (solo se envía el prefijo SHA-1, nunca tu contraseña).
- **Bóveda Cifrada Exportable:** Cifra y exporta notas o JSONs usando **AES-GCM** y derivación de claves con **Argon2id** (o PBKDF2).
- **Generador de TOTP (2FA):** Crea secretos Base32 y genera códigos QR compatibles con Google Authenticator o Authy.
- **Perfiles de Cumplimiento (Compliance):** Fuerza la generación de contraseñas bajo normativas estrictas como **Active Directory, AWS IAM, PCI-DSS o NIST 800-63B**.
- **Tokens API & Nube:** Genera cadenas Hexadecimales, URL-Safe, Bearer Tokens y UUIDv4 nativos.

---

## 🛡️ Seguridad y Criptografía

La seguridad es el pilar de CipherPass. Este proyecto implementa estándares de la industria:

- **Cifrado en reposo (Bóveda):** `AES-GCM` (Autenticación cifrada) asegurando confidencialidad e integridad.
- **Derivación de Claves (KDF):** Usa `Argon2id` (configurado para consumir 256MB de RAM y prevenir ataques por GPU) y `PBKDF2-SHA256` como respaldo.
- **Generación de Entropía:** Utiliza `secrets.SystemRandom()` (CSPRNG del sistema operativo), nunca generadores pseudoaleatorios predecibles como `random`.
- **Saneamiento de Memoria:** Destrucción explícita (`del`) de contraseñas maestras y claves en memoria inmediatamente después de usarse.
- **Base de datos Diceware:** Los diccionarios de palabras están cifrados localmente usando simetría `Fernet`.

---

## 🚀 Instalación

### Opción 1: Instalar mediante paquete `.deb` (Debian/Ubuntu)
Si estás en Linux, puedes instalar la aplicación nativa compilada directamente:

```bash
# Descarga el paquete (reemplaza con la versión actual)
wget https://github.com/tu-usuario/CipherPass_Pro/releases/download/v1.0.3/cipherpass_1.0.3_amd64.deb

# Instala el paquete
sudo dpkg -i cipherpass_1.0.3_amd64.deb

# Si faltan dependencias, ejecuta:
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
El código base y la aplicación *Free* están disponibles para uso personal. El uso de las funcionalidades avanzadas está restringido por los [Términos y Condiciones de CipherPass PRO].