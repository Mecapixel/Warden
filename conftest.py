# Root conftest so tests can import the proxy package from the repo root.
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
