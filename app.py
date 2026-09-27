"""
Quantum_NIDS_AI — launcher
==========================

Starts the dashboard from the project root so relative artifact paths resolve:

    python app.py

Equivalent to: streamlit run dashboard.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard.py"


def main() -> int:
    if not DASHBOARD.exists():
        print(f"Dashboard not found at {DASHBOARD}")
        return 1

    for folder in ("models", "results", "results/plots", "data/processed", "logs", "config"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)

    print("Starting Quantum_NIDS_AI on http://localhost:8501")
    return subprocess.call([
        sys.executable, "-m", "streamlit", "run", str(DASHBOARD),
        "--server.port", "8501",
        "--theme.base", "dark",
        "--theme.backgroundColor", "#07090F",
        "--theme.secondaryBackgroundColor", "#0B0E15",
        "--theme.textColor", "#F5F5F5",
        "--theme.primaryColor", "#6D5BF5",
    ])


if __name__ == "__main__":
    raise SystemExit(main())
