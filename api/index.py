import os
import sys

# Ensure the root directory is in the Python path for Vercel
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
