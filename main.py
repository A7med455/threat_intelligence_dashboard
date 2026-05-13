# main.py
# Click the RUN button - works from any folder

import subprocess
import os
import sys

if __name__ == "__main__":
    # Get the folder where this main.py file is located
    project_folder = os.path.dirname(os.path.abspath(__file__))
    
    # Change to that folder
    os.chdir(project_folder)
    
    # Now run streamlit
    subprocess.run([sys.executable, "-m", "streamlit", "run", "ui/dashboard.py"])