print("=" * 50)
print("🚀 Test Server")
print("=" * 50)
print("\n✅ Virtual Environment is working!")
print(f"📁 Current directory: test.py location")
print("\n🌐 Server will start at: http://localhost:8000")
print("🔍 Press Ctrl+C to stop\n")

from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Server is working perfectly!"}

@app.get("/health")
def health():
    return {"status": "healthy", "env": "virtual environment active"}

if __name__ == "__main__":
    print("🚀 Starting server...")
    uvicorn.run(app, host="127.0.0.1", port=8000)