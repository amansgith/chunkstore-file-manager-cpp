#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include "FileManager.h"
#include "ThreadPool.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

int main()
{
    init_directories();
    httplib::SSLServer svr("C:/Projects/FileManager/server.crt", "C:/Projects/FileManager/server.key");

    // POST /files - Upload Files (Multiple Files)
    svr.Post("/files", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            if (req.files.empty()) {
                res.status = 400;
                res.set_content("No files provided", "text/plain");
                return;
            }

            json response = json::array();
            std::vector<std::jthread> threads;
            std::mutex response_mutex;

            for (const auto &file_entry : req.files) {
                const auto &file = file_entry.second;
                std::string filename = file.filename;
                std::string content_type = file.content_type.empty() ? "application/octet-stream" : file.content_type;
                std::vector<char> file_data(file.content.begin(), file.content.end());

                threads.emplace_back([&response, &response_mutex, filename, content_type, file_data]() {
                    try {
                        std::string cid;
                        bool success = chunk_and_store_file(filename, content_type, file_data, cid);
                        if (success) {
                            json file_info;
                            file_info["filename"] = filename;
                            file_info["cid"] = cid;
                            {
                                std::lock_guard<std::mutex> lock(response_mutex); // Fixed: Use response_mutex
                                response.push_back(file_info);
                            }
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing file " << filename << ": " << e.what() << "\n";
                    }
                });
            }

            threads.clear(); // Wait for threads to join

            res.status = 200;
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    // PUT /files/{cid} - Update File
    svr.Put(R"(/files/(.+))", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            std::string cid = req.matches[1];

            if (req.files.find("file") == req.files.end()) {
                res.status = 400;
                res.set_content("No file provided", "text/plain");
                return;
            }

            const auto& file = req.files.find("file")->second;
            std::string content_type = file.content_type.empty() ? "application/octet-stream" : file.content_type;
            std::vector<char> file_data(file.content.begin(), file.content.end());

            if (file_data.empty()) {
                res.status = 400;
                res.set_content("File data is empty", "text/plain");
                return;
            }

            bool success = update_file(cid, content_type, file_data, true);
            if (success) {
                res.set_content("File updated successfully", "text/plain");
            } else {
                res.status = 500;
                res.set_content("Failed to update file", "text/plain");
            }
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    // GET /files/{cid} - Retrieve File
    svr.Get(R"(/files/(.+))", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            std::string cid = req.matches[1];
            std::vector<char> file_data = read_and_reassemble_file(cid, true);

            if (file_data.empty()) {
                res.status = 404;
                res.set_content("File is empty or corrupted", "text/plain");
                return;
            }

            std::string metadata_path = "C:/Projects/FileManager/metadata/" + cid + ".json";
            std::string content_type = "application/octet-stream";
            if (fs::exists(metadata_path)) {
                std::ifstream meta_file(metadata_path);
                if (meta_file.is_open()) {
                    try {
                        json metadata;
                        meta_file >> metadata;
                        if (metadata.contains("content_type")) {
                            content_type = metadata["content_type"];
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "Failed to parse metadata for content type: " << e.what() << "\n";
                    }
                }
            }

            res.set_content(std::string(file_data.begin(), file_data.end()), content_type);
        } catch (const std::exception& e) {
            res.status = 404;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    // GET /chunk/{hash} - Retrieve Chunk
    svr.Get(R"(/chunk/(.+))", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            std::string chunkname = req.matches[1];
            std::string chunk_path = "C:/Projects/FileManager/chunks/" + chunkname;

            if (!fs::exists(chunk_path)) {
                res.status = 404;
                res.set_content("Chunk not found", "text/plain");
                return;
            }

            std::ifstream chunk_file(chunk_path, std::ios::binary);
            if (!chunk_file.is_open()) {
                res.status = 500;
                res.set_content("Failed to read chunk", "text/plain");
                return;
            }
            std::vector<char> chunk_data((std::istreambuf_iterator<char>(chunk_file)), std::istreambuf_iterator<char>());

            if (chunk_data.empty()) {
                res.status = 404;
                res.set_content("Chunk is empty", "text/plain");
                return;
            }

            res.set_content(std::string(chunk_data.begin(), chunk_data.end()), "application/octet-stream");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    // DELETE /files/{cid} - Delete File
    svr.Delete(R"(/files/(.+))", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            std::string cid = req.matches[1];
            bool success = delete_file(cid, true);
            if (success) {
                res.set_content("File deleted successfully", "text/plain");
            } else {
                res.status = 404;
                res.set_content("File not found or could not be deleted", "text/plain");
            }
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    // GET /files - List all files
    svr.Get("/files", [](const httplib::Request &req, httplib::Response &res)
    {
        try {
            std::vector<nlohmann::json> metadata_list = list_files_metadata();
            json response = metadata_list;
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content("Error: " + std::string(e.what()), "text/plain");
        }
    });

    std::cout << "Server starting on port 443..." << std::endl;
    svr.listen("::", 443); // IPv6 for localhost compatibility
    return 0;
}