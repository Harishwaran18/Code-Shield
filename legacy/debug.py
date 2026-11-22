import sys
import os
import socket

print("=" * 50)
print("🔍 Debugging SecureHack AI")
print("=" * 50)

# Check Python version
print(f"✅ Python version: {sys.version}")

# Check current directory
print(f"📁 Current directory: {os.getcwd()}")

# Check if app.py exists
if os.path.exists("app.py"):
    print("✅ app.py found")
else:
    print("❌ app.py NOT found!")
    sys.exit(1)

# Check HTML files
for file in ["login.html", "editor.html"]:
    if os.path.exists(file):
        print(f"✅ {file} found")
    else:
        print(f"❌ {file} NOT found!")

# Check if port 8000 is available
def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result != 0

if check_port(8000):
    print("✅ Port 8000 is available")
else:
    print("❌ Port 8000 is already in use!")
    print("   Run: netstat -ano | findstr :8000")
    print("   Then kill the process using that port")

print("=" * 50)
print("\n📝 Next steps:")
print("1. Run: python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000")
print("2. Open browser to: http://127.0.0.1:8000")
print("=" * 50)