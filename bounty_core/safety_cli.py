"""Run the safety incident CLI without pre-importing its module via package exports."""
from .safety_incidents import main

if __name__ == "__main__":
    raise SystemExit(main())
