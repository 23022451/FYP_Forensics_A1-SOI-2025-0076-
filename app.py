"""
Wrapper app.py for Streamlit Cloud deployment
This imports and runs the actual app from the nested folder
"""

import sys
import os

# Add the nested folder to Python path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "AI and Machine Learning Features and Python Scripting"))

# Import and run the actual app
from app import *
