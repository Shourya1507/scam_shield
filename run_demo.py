"""Single entrypoint that ties everything together. Run as:
    python main.py
to execute the demo, or import GuardianAgent for programmatic use.
"""
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

sys.path.insert(0, os.path.dirname(__file__))

from agents.guardian_agent import GuardianAgent
from demo.demo_script import run_demo

if __name__ == "__main__":
    print("ScamShield AI — running full multi-agent demo\n")
    run_demo()
