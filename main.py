# main.py
# ENTRY POINT - Click the RUN button in VS Code to start the dashboard

import subprocess
import sys
import os

if __name__ == "__main__":
    # Get the folder where this main.py file is located
    project_folder = os.path.dirname(os.path.abspath(__file__))
    
    # Change to that folder
    os.chdir(project_folder)
    
    # Path to dashboard
    dashboard_path = os.path.join(project_folder, "ui", "dashboard.py")
    
    # Run streamlit
    subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path])