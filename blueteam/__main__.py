"""Entry point:  python -m blueteam <passwd|secrets|baseline|check|logs> ..."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
