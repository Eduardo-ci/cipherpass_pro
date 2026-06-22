#!/usr/bin/env python3
import argparse
import sys
import getpass
import json
import pyperclip
from zxcvbn import zxcvbn
from rich.console import Console
from rich.table import Table

from cipherpass_core.generators import PasswordEngine, TOTPEngine
from cipherpass_core.hibp import HIBPClient
from cipherpass_core.crypto_vault import VaultExporter

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="CipherPass CLI - Advanced Cryptographic Tool\nSecurely generate passwords, tokens, check data breaches, and manage encrypted vaults.",
        epilog="""
Examples of common tasks:
  1. Generate a 20-character password, analyze it and copy to clipboard:
     cipherpass-cli generate -l 20 --analyze --copy
  
  2. Generate a TOTP secret for an authenticator app:
     cipherpass-cli totp -a user@example.com -i MyCompany
  
  3. Check if a password was exposed in data breaches (interactive):
     cipherpass-cli hibp
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted text (useful for scripting)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # --- Comando: generate ---
    gen_parser = subparsers.add_parser(
        "generate", 
        help="Generates a secure password",
        description="Generates a cryptographically secure random password using the system's CSPRNG.",
        epilog="""
Examples:
  cipherpass-cli generate                        (Default 16 chars)
  cipherpass-cli generate -l 24 --no-syms -c     (24 chars, no symbols, copy)
  cipherpass-cli generate --analyze              (Show entropy and crack time)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    gen_parser.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    gen_parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    gen_parser.add_argument("--no-nums", action="store_true", help="Exclude numbers")
    gen_parser.add_argument("--no-syms", action="store_true", help="Exclude symbols")
    gen_parser.add_argument("--avoid-ambiguous", action="store_true", help="Avoid ambiguous characters (I, l, 1, O, 0)")
    gen_parser.add_argument("-c", "--copy", action="store_true", help="Copy output to clipboard")
    gen_parser.add_argument("--analyze", action="store_true", help="Analyze password entropy and strength")

    # --- Comando: totp ---
    totp_parser = subparsers.add_parser(
        "totp", 
        help="Generates a TOTP secret and URI",
        description="Generates a Time-Based One-Time Password (TOTP) secret base32 key and its provisioning URI (otpauth://).",
        epilog="""
Examples:
  cipherpass-cli totp -a admin@company.com -i "Prod Server"
  cipherpass-cli totp -a user -i "Local VPN" --copy
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    totp_parser.add_argument("-a", "--account", required=True, help="Account name for the TOTP URI")
    totp_parser.add_argument("-i", "--issuer", required=True, help="Issuer for the TOTP URI")
    totp_parser.add_argument("-c", "--copy", action="store_true", help="Copy output to clipboard")

    # --- Comando: token ---
    token_parser = subparsers.add_parser(
        "token", 
        help="Generates a secure token for APIs or a UUID v4",
        description="Generates random URL-safe or hexadecimal tokens, Bearer strings, or UUIDs for API keys or session identifiers.",
        epilog="""
Examples:
  cipherpass-cli token -m 0 -l 64     (64-byte URL-safe token)
  cipherpass-cli token -m 2           (Standard UUID v4)
  cipherpass-cli token -m 3 -l 32     (Bearer token)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    token_parser.add_argument("-m", "--mode", type=int, choices=[0, 1, 2, 3], default=0, help="Token type (0: URL-safe, 1: Hexadecimal, 2: UUIDv4, 3: Bearer)")
    token_parser.add_argument("-l", "--length", type=int, default=32, help="Length in bytes for modes 0, 1 and 3 (default: 32)")
    token_parser.add_argument("-c", "--copy", action="store_true", help="Copy output to clipboard")

    # --- Comando: hibp ---
    # SEGURIDAD (A-03): La contraseña se pide con getpass para evitar que
    # quede expuesta en el historial del shell o en la lista de procesos (ps aux).
    hibp_parser = subparsers.add_parser(
        "hibp", 
        help="Checks if a password has been exposed in data breaches",
        description="Checks the Have I Been Pwned API using K-Anonymity. The password is never sent in plaintext; only the first 5 characters of its SHA-1 hash are transmitted.",
        epilog="""
Examples:
  cipherpass-cli hibp                     (Prompts securely without showing chars)
  echo "mypassword" | cipherpass-cli hibp (Reads from stdin for scripts)
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # --- Comando: vault-export ---
    # SEGURIDAD (B-03): Se elimina el flag -p/--password para evitar que la
    # contraseña maestra quede en el historial del shell o en la lista de procesos.
    # La contraseña siempre se pide de forma interactiva con getpass.
    vault_export_parser = subparsers.add_parser(
        "vault-export", 
        help="Encrypts text/JSON for the vault (AES-GCM)",
        description="Encrypts arbitrary text using AES-256-GCM. The master key is derived securely via PBKDF2 or Argon2id.",
        epilog="""
Examples:
  echo '{"secret": 123}' | cipherpass-cli vault-export - --argon2 > vault.cpv
  cipherpass-cli vault-export "My secret message"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    vault_export_parser.add_argument("data", help="Text to encrypt (use '-' to read from stdin)")
    vault_export_parser.add_argument("--argon2", action="store_true", help="Use Argon2id for key derivation")

    # --- Comando: vault-import ---
    # SEGURIDAD (B-03): Igual que vault-export, la contraseña siempre se pide
    # de forma interactiva para no exponerla en el historial ni en los procesos.
    vault_import_parser = subparsers.add_parser(
        "vault-import", 
        help="Decrypts an exported vault (AES-GCM)",
        description="Decrypts a vault file or string using the master password.",
        epilog="""
Examples:
  cat vault.cpv | cipherpass-cli vault-import -
  cipherpass-cli vault-import "eyJhbG..." 
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    vault_import_parser.add_argument("data", help="JSON of the encrypted vault (use '-' to read from stdin)")

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
        
        if args.json:
            print(json.dumps({"password": pwd, "length": len(pwd)}))
        else:
            if args.copy:
                pyperclip.copy(pwd)
                console.print("[bold green]✔ Password copied to clipboard![/bold green]")
            else:
                console.print(f"[bold cyan]{pwd}[/bold cyan]")
                
            if args.analyze:
                analysis = zxcvbn(pwd)
                table = Table(title="Password Analysis")
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="magenta")
                table.add_row("Score", f"{analysis['score']} / 4")
                table.add_row("Entropy (Guesses)", str(analysis['guesses']))
                table.add_row("Crack Time", analysis['crack_times_display']['offline_fast_hashing_1e10_per_second'])
                if analysis['feedback']['warning']:
                    table.add_row("Warning", f"[red]{analysis['feedback']['warning']}[/red]")
                console.print(table)

    elif args.command == "totp":
        secret = TOTPEngine.generate_secret()
        uri = TOTPEngine.build_uri(secret, account_name=args.account, issuer=args.issuer)
        if args.json:
            print(json.dumps({"totp_secret": secret, "totp_uri": uri}))
        else:
            if args.copy:
                pyperclip.copy(uri)
                console.print("[bold green]✔ TOTP URI copied to clipboard![/bold green]")
            else:
                console.print(f"Secret: [bold cyan]{secret}[/bold cyan]")
                console.print(f"URI: [bold cyan]{uri}[/bold cyan]")

    elif args.command == "token":
        engine = PasswordEngine()
        token = engine.generate_api_token(mode=args.mode, length=args.length)
        if args.json:
            print(json.dumps({"token": token, "mode": args.mode}))
        else:
            if args.copy:
                pyperclip.copy(token)
                console.print("[bold green]✔ Token copied to clipboard![/bold green]")
            else:
                console.print(f"[bold cyan]{token}[/bold cyan]")

    elif args.command == "hibp":
        if not sys.stdin.isatty():
            password = sys.stdin.read().strip()
        else:
            password = getpass.getpass("🔑 Password to check (hidden): ")
            
        count, error = HIBPClient.check_password(password)
        del password
        
        if args.json:
            print(json.dumps({"exposed": count > 0, "count": count, "error": error}))
        else:
            if error:
                console.print(f"[bold yellow]❌ Error: {error}[/bold yellow]")
            elif count > 0:
                console.print(f"[bold red]⚠ Exposed {count} times[/bold red]")
            else:
                console.print(f"[bold green]✔ Safe (0 times)[/bold green]")
        
    elif args.command == "vault-export":
        data = sys.stdin.read() if args.data == '-' else args.data
        password = getpass.getpass("🔑 Master password: ")
        exporter = VaultExporter()
        result = exporter.export_vault(data, password, args.argon2)
        del password
        
        if args.json:
            print(json.dumps({"vault": result}))
        else:
            console.print(f"[bold cyan]{result}[/bold cyan]")
        
    elif args.command == "vault-import":
        data = sys.stdin.read() if args.data == '-' else args.data
        password = getpass.getpass("🔑 Master password: ")
        exporter = VaultExporter()
        result = exporter.import_vault(data, password)
        del password
        
        if result:
            if args.json:
                print(json.dumps({"data": result}))
            else:
                console.print(result)
        else:
            if args.json:
                print(json.dumps({"error": "Incorrect password or corrupted data"}))
            else:
                console.print("[bold red]❌ Error: Incorrect password or corrupted data.[/bold red]")
            sys.exit(1)
            
    else:
        parser.print_help()

if __name__ == "__main__":
    main()