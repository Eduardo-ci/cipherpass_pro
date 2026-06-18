# Manual de Uso: CipherPass CLI

`cipherpass-cli` es una herramienta criptográfica diseñada para SysAdmins que ofrece funcionalidades como la generación de contraseñas, validación en bases de datos de contraseñas expuestas y cifrado/descifrado seguro de datos (bóvedas).

## Uso Básico
```bash
cipherpass-cli [comando] [argumentos...]
```

---

## Comandos Disponibles

A continuación se detallan los comandos soportados, su propósito y los argumentos que aceptan.

### 1. `generate`
Genera una contraseña segura y criptográficamente fuerte.

**Argumentos opcionales:**
*   `-l`, `--length <entero>`: Define la longitud de la contraseña generada (por defecto es `16`).
*   `--no-upper`: Excluye las letras mayúsculas de la contraseña.
*   `--no-nums`: Excluye los números.
*   `--no-syms`: Excluye los símbolos o caracteres especiales.
*   `--avoid-ambiguous`: Evita incluir caracteres ambiguos que pueden ser fáciles de confundir visualmente (como `I`, `l`, `1`, `O`, `0`).

**Ejemplos de uso:**
```bash
# Generar una contraseña estándar de 16 caracteres
cipherpass-cli generate

# Generar una contraseña de 24 caracteres sin símbolos ni caracteres ambiguos
cipherpass-cli generate -l 24 --no-syms --avoid-ambiguous
```

---

### 2. `totp`
Genera un nuevo secreto aleatorio en Base32, listo para ser utilizado en aplicaciones de autenticación de dos factores (TOTP) como Google Authenticator o Authy.

**Argumentos:**
*   *(No requiere argumentos adicionales)*

**Ejemplo de uso:**
```bash
cipherpass-cli totp
```

---

### 3. `hibp`
Comprueba si una contraseña ha sido expuesta en filtraciones de datos, haciendo uso de la API de *Have I Been Pwned* (HIBP).

**🛡️ Seguridad Integrada:** Para prevenir la filtración de tu contraseña, esta **nunca** se pasa como argumento de la línea de comandos (evitando que quede expuesta en el `history` del shell o al comando `ps`). La herramienta te la solicitará de forma segura (oculta) durante la ejecución.

**Argumentos:**
*   *(No requiere argumentos adicionales)*

**Ejemplo de uso:**
```bash
cipherpass-cli hibp
# La consola solicitará: "🔑 Contraseña a verificar (oculta): "
```

---

### 4. `vault-export`
Cifra un texto o información confidencial utilizando AES-GCM para ser almacenado en una bóveda segura, produciendo un archivo JSON con los datos cifrados.

**🛡️ Seguridad Integrada:** La contraseña maestra de la bóveda siempre se solicita de manera interactiva.

**Argumentos:**
*   `data` *(requerido)*: El texto que deseas cifrar. Puedes proporcionar el texto directamente, o usar el guion `-` para que la herramienta lea la información desde la entrada estándar (*stdin*).
*   `--argon2` *(opcional)*: Fuerza el uso del algoritmo Argon2id para derivar la clave criptográfica en lugar del algoritmo predeterminado. Esto brinda una mayor seguridad frente a ataques de fuerza bruta.

**Ejemplos de uso:**
```bash
# Pasando el texto como argumento (requiere entrecomillado si hay espacios)
cipherpass-cli vault-export "Mi información ultrasecreta" --argon2

# Usando la entrada estándar (ideal para scripts o pipes)
echo "Texto secreto" | cipherpass-cli vault-export -
```

---

### 5. `vault-import`
Recibe los datos en formato JSON de una bóveda previamente exportada y los descifra, devolviendo el texto original en plano.

**🛡️ Seguridad Integrada:** La contraseña maestra de la bóveda siempre se solicita de manera interactiva.

**Argumentos:**
*   `data` *(requerido)*: El JSON que contiene los datos cifrados. También acepta `-` para leer desde la entrada estándar.

**Ejemplos de uso:**
```bash
# Pasando el JSON directamente como argumento
cipherpass-cli vault-import '{"iv": "...", "salt": "...", "ciphertext": "..."}'

# Leyendo el archivo exportado a través de la entrada estándar
cat boveda.json | cipherpass-cli vault-import -
```

---

### 6. `token`
Genera un token seguro para ser utilizado en APIs, servicios en la nube, o identificadores únicos universales (UUID v4).

**Argumentos opcionales:**
*   `-m`, `--mode <0|1|2|3>`: Especifica el formato del token generado. (Por defecto: `0`).
    *   `0`: URL-safe (Base64url sin relleno). Ideal para tokens de sesión y URLs.
    *   `1`: Hexadecimal. Ideal para hashes o claves simétricas puras.
    *   `2`: UUID v4. Formato estándar universal.
    *   `3`: Bearer Token. Mismo que el modo `0` pero con el prefijo `Bearer `.
*   `-l`, `--length <entero>`: Define la longitud del token en bytes para los modos 0, 1 y 3 (Por defecto: `32`). *Nota: Un token URL-safe o Hexadecimal será más largo en caracteres finales.*

**Ejemplos de uso:**
```bash
# Generar un token URL-safe de 32 bytes (comportamiento por defecto)
cipherpass-cli token

# Generar un UUID v4 estándar
cipherpass-cli token --mode 2

# Generar un token Hexadecimal de 16 bytes
cipherpass-cli token -m 1 -l 16

# Generar un token Bearer para usar en cabeceras HTTP de 64 bytes
cipherpass-cli token -m 3 -l 64
```

