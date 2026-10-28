"""Put capture-browser/ on sys.path so tests can `import capture.spool` (no Playwright)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
