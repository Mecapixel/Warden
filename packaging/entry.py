"""PyInstaller entry point for the packaged `warden` binary."""
import sys
from warden.cli import main

if __name__ == "__main__":
    sys.exit(main())