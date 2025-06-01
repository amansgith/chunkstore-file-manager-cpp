# ChunkStore File Manager (C++)

ChunkStore is a C++ microservice that simulates core IPFS-like functionality for local file storage. It performs content-addressed chunking, deduplication, and exposes a REST API for CRUD operations on files and individual chunks.

---

## ✨ Features
- Split files into 1MB chunks with SHA-256 hashing
- Deduplicates chunks based on hash identity
- Stores JSON metadata for each file (filename, size, chunks, timestamps)
- CRUD support via RESTful API using `cpp-httplib`
- Retrieve full file or individual chunk by hash
- Partial file updates by detecting modified chunks

---

## 📦 API Endpoints

| Method | Endpoint                | Description                     |
|--------|-------------------------|---------------------------------|
| POST   | `/files`                | Upload and chunk a file         |
| GET    | `/files/{filename}`     | Retrieve and reconstruct a file |
| GET    | `/chunks/{hash}`        | Fetch specific chunk by hash    |
| DELETE | `/files/{filename}`     | Delete file and unused chunks   |
| PUT    | `/files/{filename}`     | Update file, reusing old chunks |

---

## 🛠 Requirements

Make sure the following are pre-installed on your system (Installation guides may vary according to OS):

- [cpp-httplib](https://github.com/yhirose/cpp-httplib)
- C++20 compatible compiler
- [CMake ≥ 3.15](https://cmake.org/download/)
- [OpenSSL](https://www.openssl.org/)
- [nlohmann_json](https://github.com/nlohmann/json)
- [vcpkg](https://github.com/microsoft/vcpkg) (optional, for dependency management)

---

## 🔧 Build Instructions

```bash
# Clone the repo
$ git clone https://github.com/yourname/chunkstore-file-manager-cpp.git
$ cd chunkstore-file-manager-cpp

# Create build directory and compile
$ mkdir build && cd build
$ cmake ..
$ camke --build . --config release
$ cd release (if release folder gets created.. if ninja build is installed then it may not get created)
```

---

## 🚀 Now Run Server

```bash
./file_manager.exe
```

The server starts at `http://localhost:443`.

---

## 🧪 Example Usage

Use `curl` or Postman to interact:

```bash
curl -X POST -F 'file=@mydoc.pdf' http://localhost:8080/files
curl http://localhost:8080/files/mydoc.pdf -o output.pdf
```

---

## 📁 Project Structure
```
chunkstore-file-manager-cpp/
├── .vscode/              # VS Code workspace settings
├── build/                # CMake build artifacts
│   ├── CMakeFiles/
│   └── CMakeCache.txt
├── src/
│   ├── FileManager.cpp
│   ├── FileManager.h
│   ├── ThreadPool.cpp
│   ├── ThreadPool.h
│   └── main.cpp
├── .gitignore
├── CMakeLists.txt
└── README.md
```

---

## 📜 License
MIT License
