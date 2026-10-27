"""Put capture-proxy/ on sys.path so tests can `import proxy` / `import ip_blocklist`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
