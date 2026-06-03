from app import install_worker
try:
    print("Triggering install...")
    # Passing empty config so it uses default from catalog
    # Passing 'admin' as user
    install_worker('phpmyadmin', {}, 'admin')
    print("Install finished.")
except Exception as e:
    print(f"Error: {e}")
