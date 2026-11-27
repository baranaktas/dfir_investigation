"""Stand-in for `vol -q -r jsonl -f IMAGE PLUGIN`: prints canned output for the tests."""
import os
import sys
import time
from pathlib import Path

plugin = sys.argv[-1]
if os.environ.get("FAKE_VOL_SLEEP"):
    time.sleep(float(os.environ["FAKE_VOL_SLEEP"]))
if plugin == "windows.netscan":
    print("Volatility experienced an error: netscan failed", file=sys.stderr)
    sys.exit(1)
fixture = Path(__file__).with_name(plugin + ".jsonl")
if not fixture.exists():
    print(f"unknown plugin {plugin}", file=sys.stderr)
    sys.exit(2)
sys.stdout.write(fixture.read_text())
