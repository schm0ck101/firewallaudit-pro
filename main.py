"""Lanceur de FirewallAudit Pro (utilisé aussi par PyInstaller)."""
import sys

from fwaudit.app import main

if __name__ == "__main__":
    sys.exit(main())
