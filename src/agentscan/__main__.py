"""Enable `python -m agentscan`."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
