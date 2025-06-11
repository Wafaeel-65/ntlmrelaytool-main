# cleanup.py

import os
import shutil

def cleanup_temp_files(temp_dir):
    """Remove temporary files from the specified directory."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"Cleaned up temporary files in {temp_dir}")
    else:
        print(f"No temporary directory found at {temp_dir}")

if __name__ == "__main__":
    temp_directory = "path/to/temp/directory"  # Specify the path to the temporary directory
    cleanup_temp_files(temp_directory)