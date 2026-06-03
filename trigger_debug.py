from app import install_worker
import traceback
import sys

try:
    print("Triggering install...")
    # Passing empty config so it uses default from catalog
    # Passing 'admin' as user
    install_worker('homeassistant', {}, 'admin')
    print("Install finished.")
except Exception as e:
    print(f"Error executing install_worker:")
    traceback.print_exc()
    sys.exit(1)
