#!/usr/bin/env python3
import argparse
import sys
import getpass

from cipherpass_core.generators import PasswordEngine, TOTPEngine
from cipherpass_core.hibp import HIBPClient
from cipherpass_core.crypto_vault import VaultExporter

def main():
    parser = argparse.ArgumentParser(description="CipherPass CLI - Herramienta criptográfica para SysAdmins")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # --- Comando: generate ---
    gen_parser = subparsers.add_parser("generate", help="Genera una contraseña segura")
    gen_parser.add_argument("-l", "--length", type=int, default=16, help="Longitud de la contraseña (default: 16)")
    gen_parser.add_argument("--no-upper", action="store_true", help="Excluye letras mayúsculas")
    gen_parser.add_argument("--no-nums", action="store_true", help="Excluye números")
    gen_parser.add_argument("--no-syms", action="store_true", help="Excluye símbolos")
    gen_parser.add_argument("--avoid-ambiguous", action="store_true", help="Evita caracteres ambiguos (I, l, 1, O, 0)")

    # --- Comando: totp ---
    totp_parser = subparsers.add_parser("totp", help="Genera un secreto TOTP")

    # --- Comando: hibp ---
    hibp_parser = subparsers.add_parser("hibp", help="Comprueba si una contraseña ha sido expuesta")
    hibp_parser.add_argument("password", type=str, help="Contraseña a verificar")

    # --- Comando: vault-export ---
    vault_export_parser = subparsers.add_parser("vault-export", help="Cifra un texto para la bóveda (AES-GCM)")
    vault_export_parser.add_argument("data", help="Texto a cifrar (usa '-' para leer de la entrada estándar)")
    vault_export_parser.add_argument("-p", "--password", help="Contraseña maestra (si se omite, se pedirá de forma segura)")
    vault_export_parser.add_argument("--argon2", action="store_true", help="Usar Argon2id para derivación de claves")

    # --- Comando: vault-import ---
    vault_import_parser = subparsers.add_parser("vault-import", help="Descifra una bóveda exportada")
    vault_import_parser.add_argument("data", help="JSON de la bóveda cifrada (usa '-' para leer de la entrada estándar)")
    vault_import_parser.add_argument("-p", "--password", help="Contraseña maestra (si se omite, se pedirá de forma segura)")

    args = parser.parse_args()

    if args.command == "generate":
        engine = PasswordEngine()
        pwd = engine.generate_password(
            length=args.length,
            min_nums=0 if args.no_nums else 1,
            min_specs=0 if args.no_syms else 1,
            use_upper=not args.no_upper,
            use_lower=True,
            use_nums=not args.no_nums,
            use_syms=not args.no_syms,
            avoid_amb=args.avoid_ambiguous
        )
        print(pwd)
    elif args.command == "totp":
        print(TOTPEngine.generate_secret())
    elif args.command == "hibp":
        count, error = HIBPClient.check_password(args.password)
        print(f"Expuesta {count} veces" if count > 0 else ("Segura (0 veces)" if count == 0 else f"Error: {error}"))
        
    elif args.command == "vault-export":
        data = sys.stdin.read() if args.data == '-' else args.data
        password = args.password or getpass.getpass("🔑 Contraseña maestra: ")
        exporter = VaultExporter()
        print(exporter.export_vault(data, password, args.argon2))
        
    elif args.command == "vault-import":
        data = sys.stdin.read() if args.data == '-' else args.data
        password = args.password or getpass.getpass("🔑 Contraseña maestra: ")
        exporter = VaultExporter()
        result = exporter.import_vault(data, password)
        if result:
            print(result)
        else:
            print("❌ Error: Contraseña incorrecta o datos corruptos.", file=sys.stderr)
            sys.exit(1)
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()