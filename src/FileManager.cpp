#include "FileManager.h"
#include "ThreadPool.h"
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <unordered_map>

namespace fs = std::filesystem;
using json = nlohmann::json;

const size_t CHUNK_SIZE = 1024 * 1024; // 1MB
const std::string CHUNK_DIR = "C:/Projects/FileManager/chunks";
const std::string METADATA_DIR = "C:/Projects/FileManager/metadata";

// Global mutex to protect metadata file access
std::mutex metadata_mutex;

// Initialize directories
void init_directories()
{
    try
    {
        fs::create_directories(CHUNK_DIR);
        fs::create_directories(METADATA_DIR);
        std::cout << "Created directories: " << CHUNK_DIR << " and " << METADATA_DIR << "\n";
    }
    catch (const fs::filesystem_error &e)
    {
        std::cerr << "Failed to create directories: " << e.what() << "\n";
        throw;
    }
}

// Compute SHA-256 hash for the entire file data
std::string compute_file_hash(const std::vector<char> &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(), hash);

    std::ostringstream oss;
    for (unsigned char c : hash)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

// Find existing metadata for a file hash (CID) and return its path and chunk hashes
bool find_duplicate_metadata(const std::string &cid, std::string &metadata_path, std::vector<std::string> &chunk_hashes)
{
    std::lock_guard<std::mutex> lock(metadata_mutex);
    for (const auto &entry : fs::directory_iterator(METADATA_DIR))
    {
        if (entry.path().extension() == ".json")
        {
            std::ifstream meta_file(entry.path());
            if (!meta_file.is_open()) continue;
            try
            {
                json metadata;
                meta_file >> metadata;
                if (metadata.contains("cid") && metadata["cid"] == cid)
                {
                    metadata_path = entry.path().string();
                    if (metadata.contains("chunks"))
                    {
                        for (const auto &chunk : metadata["chunks"])
                        {
                            chunk_hashes.push_back(chunk["hash"].get<std::string>());
                        }
                    }
                    return true;
                }
            }
            catch (const json::exception& e)
            {
                std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                continue;
            }
        }
    }
    return false;
}

// Chunk file, store metadata, and perform deduplication
bool chunk_and_store_file(const std::string &filename, const std::string &content_type, const std::vector<char> &file_data, std::string &cid) {
    // Validate filename
    if (filename.empty() || filename.find("..") != std::string::npos || filename.find('/') != std::string::npos || filename.find('\\') != std::string::npos) {
        throw std::runtime_error("Invalid filename");
    }

    // Compute file CID
    cid = compute_file_hash(file_data);
    std::string existing_metadata_path;
    std::vector<std::string> existing_chunk_hashes;

    // Check if the file is a duplicate
    bool is_duplicate = find_duplicate_metadata(cid, existing_metadata_path, existing_chunk_hashes);
    std::unordered_map<std::string, int> chunk_ref_counts;
    size_t total_size = file_data.size();

    // check for existing metadata and increase reference counts if it's a duplicate
    if (is_duplicate) {
        std::lock_guard<std::mutex> meta_lock(metadata_mutex);
        std::ifstream meta_file(existing_metadata_path);
        if (!meta_file.is_open()) {
            throw std::runtime_error("Failed to open existing metadata file: " + existing_metadata_path);
        }
        json metadata;
        try {
            meta_file >> metadata;
            meta_file.close();
        } catch (const json::exception &e) {
            throw std::runtime_error("Failed to parse existing metadata file " + existing_metadata_path + ": " + e.what());
        }

        // check and increase ref count of file
        int file_ref_count = metadata.contains("file_ref_count") ? metadata["file_ref_count"].get<int>() : 1;
        metadata["file_ref_count"] = file_ref_count + 1;

        // Update chunk reference counts
        if (metadata.contains("chunks")) {
            for (auto &chunk : metadata["chunks"]) {
                for (const auto &hash : existing_chunk_hashes) {
                    if (chunk["hash"] == hash) {
                        int ref_count = chunk["ref_count"].get<int>();
                        chunk["ref_count"] = ref_count + 1;
                        chunk_ref_counts[hash] = ref_count + 1;
                        break;
                    }
                }
            }
        }

        std::ofstream updated_meta_file(existing_metadata_path);
        if (!updated_meta_file.is_open()) {
            throw std::runtime_error("Failed to update metadata file: " + existing_metadata_path);
        }
        updated_meta_file << metadata.dump(4);
        updated_meta_file.close();
        return false;
    }

    // File is not a duplicate; chunk it and store
    size_t offset = 0;
    ThreadPool thread_pool(24);
    std::unordered_map<std::string, std::vector<char>> chunk_data_map;

    while (offset < total_size) {
        size_t bytes_to_read = std::min(CHUNK_SIZE, total_size - offset);
        std::vector<char> buffer(file_data.begin() + offset, file_data.begin() + offset + bytes_to_read);
        offset += bytes_to_read;

        thread_pool.enqueue([&chunk_data_map, buffer]() {
            std::string hash = compute_file_hash(buffer);
            {
                std::lock_guard<std::mutex> lock(metadata_mutex);
                if (chunk_data_map.find(hash) == chunk_data_map.end()) {
                    chunk_data_map[hash] = buffer;
                }
            }
        });
    }

    thread_pool.wait_for_tasks();

    for (const auto &[hash, buffer] : chunk_data_map) {
        std::string chunk_path = CHUNK_DIR + "/" + hash;
        if (!fs::exists(chunk_path)) {
            std::ofstream chunk_file(chunk_path, std::ios::binary);
            if (!chunk_file.is_open()) {
                throw std::runtime_error("Failed to write chunk: " + chunk_path);
            }
            chunk_file.write(buffer.data(), buffer.size());
            chunk_file.close();
        }
        chunk_ref_counts[hash] = chunk_ref_counts[hash] + 1;
    }

    // Create metadata
    json metadata;
    metadata["filename"] = filename;
    metadata["size"] = total_size;
    metadata["content_type"] = content_type;
    metadata["cid"] = cid;
    metadata["file_ref_count"] = 1;

    json chunks_array = json::array();
    for (const auto &[hash, buffer] : chunk_data_map) {
        chunks_array.push_back({
            {"hash", hash},
            {"ref_count", chunk_ref_counts[hash]}
        });
    }
    metadata["chunks"] = chunks_array;

    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&now_c), "%Y-%m-%dT%H:%M:%SZ");
    metadata["created_at"] = ss.str();

    // Use CID for metadata filename
    std::string metadata_path = METADATA_DIR + "/" + cid + ".json";
    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        std::ofstream meta_file(metadata_path);
        if (!meta_file.is_open()) {
            throw std::runtime_error("Failed to create metadata file: " + metadata_path);
        }
        meta_file << metadata.dump(4);
        meta_file.close();
    }

    return true;
}

std::vector<char> read_and_reassemble_file(const std::string &identifier, bool is_cid)
{
    std::string metadata_path = is_cid ? (METADATA_DIR + "/" + identifier + ".json") : (METADATA_DIR + "/" + identifier + ".json");

    if (!fs::exists(metadata_path))
    {
        throw std::runtime_error("Metadata file not found for: " + identifier);
    }

    json metadata;
    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        std::ifstream meta_file(metadata_path);
        if (!meta_file.is_open())
        {
            throw std::runtime_error("Failed to open metadata file: " + metadata_path);
        }
        try
        {
            meta_file >> metadata;
        }
        catch (const json::exception& e)
        {
            throw std::runtime_error("Failed to parse metadata file " + metadata_path + ": " + e.what());
        }
    }

    std::vector<std::string> chunk_hashes;
    if (!metadata.contains("chunks"))
    {
        throw std::runtime_error("No chunks found in metadata for: " + identifier);
    }
    for (const auto& chunk : metadata["chunks"])
    {
        chunk_hashes.push_back(chunk["hash"].get<std::string>());
    }

    std::vector<char> file_data;
    for (const std::string &hash : chunk_hashes)
    {
        std::string chunk_path = CHUNK_DIR + "/" + hash;
        if (!fs::exists(chunk_path))
        {
            throw std::runtime_error("Chunk file not found: " + chunk_path);
        }

        std::ifstream chunk_file(chunk_path, std::ios::binary);
        if (!chunk_file.is_open())
        {
            throw std::runtime_error("Failed to open chunk file: " + chunk_path);
        }
        std::vector<char> buffer((std::istreambuf_iterator<char>(chunk_file)), std::istreambuf_iterator<char>());
        file_data.insert(file_data.end(), buffer.begin(), buffer.end());
    }

    return file_data;
}

bool delete_file(const std::string &identifier, bool is_cid)
{
    std::string metadata_path = is_cid ? (METADATA_DIR + "/" + identifier + ".json") : (METADATA_DIR + "/" + identifier + ".json");

    if (!fs::exists(metadata_path)) {
        std::cout << "Metadata file not found for: " << identifier << "\n";
        return false;
    }

    json metadata;
    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        std::ifstream meta_file(metadata_path);
        if (!meta_file.is_open()) {
            std::cout << "Failed to open metadata file: " << metadata_path << "\n";
            return false;
        }
        try {
            meta_file >> metadata;
        } catch (const json::exception &e) {
            std::cout << "Failed to parse metadata file " << metadata_path << ": " << e.what() << "\n";
            return false;
        }
        meta_file.close();
    }

    int file_ref_count = metadata.contains("file_ref_count") ? metadata["file_ref_count"].get<int>() : 1;
    file_ref_count--;

    if (file_ref_count > 0) {
        if (metadata.contains("chunks")) {
            for (auto &chunk : metadata["chunks"]) {
                int ref_count = chunk["ref_count"].get<int>();
                chunk["ref_count"] = ref_count - 1;
                std::cout << "Decremented ref_count for chunk " << chunk["hash"] << " to " << (ref_count - 1) << "\n";
            }
        }

        {
            std::lock_guard<std::mutex> lock(metadata_mutex);
            metadata["file_ref_count"] = file_ref_count;
            std::ofstream updated_meta_file(metadata_path);
            if (!updated_meta_file.is_open()) {
                std::cout << "Failed to update metadata file: " << metadata_path << "\n";
                return false;
            }
            updated_meta_file << metadata.dump(4);
            updated_meta_file.close();
            std::cout << "Decremented file_ref_count for " << identifier << " to " << file_ref_count << "\n";
        }
        return true;
    }

    if (!metadata.contains("chunks")) {
        std::cout << "No chunks found in metadata for: " << identifier << "\n";
        return false;
    }

    for (const auto &chunk : metadata["chunks"]) {
        std::string chunk_hash = chunk["hash"];
        int current_ref_count = chunk["ref_count"];

        bool chunk_still_referenced = false;
        {
            std::lock_guard<std::mutex> lock(metadata_mutex);
            for (const auto &entry : fs::directory_iterator(METADATA_DIR)) {
                if (entry.path() != metadata_path && entry.path().extension() == ".json") {
                    std::ifstream other_meta_file(entry.path());
                    if (!other_meta_file.is_open()) continue;
                    try {
                        json other_metadata;
                        other_meta_file >> other_metadata;
                        other_meta_file.close();

                        if (other_metadata.contains("chunks")) {
                            for (auto &other_chunk : other_metadata["chunks"]) {
                                if (other_chunk["hash"] == chunk_hash) {
                                    int new_ref_count = other_chunk["ref_count"].get<int>() - 1;
                                    other_chunk["ref_count"] = new_ref_count;
                                    if (new_ref_count > 0) {
                                        chunk_still_referenced = true;
                                    }
                                    std::ofstream updated_meta_file(entry.path());
                                    if (updated_meta_file.is_open()) {
                                        updated_meta_file << other_metadata.dump(4);
                                        updated_meta_file.close();
                                    }
                                    break;
                                }
                            }
                        }
                    } catch (const json::exception &e) {
                        std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                        continue;
                    }
                }
            }
        }

        if (!chunk_still_referenced) {
            std::string chunk_path = CHUNK_DIR + "/" + chunk_hash;
            if (fs::exists(chunk_path)) {
                fs::remove(chunk_path);
                std::cout << "Deleted chunk: " << chunk_path << "\n";
            }
        } else {
            std::cout << "Chunk " << chunk_hash << " still referenced by another file\n";
        }
    }

    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        fs::remove(metadata_path);
    }
    std::cout << "Deleted metadata file: " << metadata_path << "\n";
    return true;
}

bool update_file(const std::string &identifier, const std::string &content_type, const std::vector<char> &file_data, bool is_cid)
{
    std::string metadata_path = is_cid ? (METADATA_DIR + "/" + identifier + ".json") : (METADATA_DIR + "/" + identifier + ".json");

    if (!fs::exists(metadata_path))
    {
        throw std::runtime_error("File not found for update: " + identifier);
    }

    json metadata;
    std::vector<std::string> old_chunk_hashes;
    int file_ref_count;
    std::string old_filename;
    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        std::ifstream meta_file(metadata_path);
        if (!meta_file.is_open())
        {
            throw std::runtime_error("Failed to open metadata file: " + metadata_path);
        }
        try
        {
            meta_file >> metadata;
            meta_file.close();
        }
        catch (const json::exception& e)
        {
            throw std::runtime_error("Failed to parse metadata file " + metadata_path + ": " + e.what());
        }

        if (!metadata.contains("chunks"))
        {
            throw std::runtime_error("No chunks found in metadata for: " + identifier);
        }
        for (const auto& chunk : metadata["chunks"])
        {
            old_chunk_hashes.push_back(chunk["hash"].get<std::string>());
        }
        file_ref_count = metadata.contains("file_ref_count") ? metadata["file_ref_count"].get<int>() : 1;
        old_filename = metadata["filename"].get<std::string>();
    }

    std::string new_cid = compute_file_hash(file_data);
    size_t total_size = file_data.size();

    size_t offset = 0;
    std::vector<std::string> new_chunk_hashes;
    std::vector<std::vector<char>> new_chunks_data;
    ThreadPool thread_pool(16);

    while (offset < total_size)
    {
        size_t bytes_to_read = std::min(CHUNK_SIZE, total_size - offset);
        std::vector<char> buffer(file_data.begin() + offset, file_data.begin() + offset + bytes_to_read);
        new_chunks_data.push_back(buffer);
        offset += bytes_to_read;

        thread_pool.enqueue([&new_chunk_hashes, buffer]()
        {
            std::string hash = compute_file_hash(buffer);
            new_chunk_hashes.push_back(hash);
        });
    }
    thread_pool.wait_for_tasks();

    std::vector<std::pair<std::string, int>> updated_chunk_hashes;
    for (size_t i = 0; i < new_chunk_hashes.size(); ++i)
    {
        std::string new_hash = new_chunk_hashes[i];
        std::vector<char>& chunk_data = new_chunks_data[i];
        int ref_count = 1;

        if (i < old_chunk_hashes.size() && new_hash == old_chunk_hashes[i])
        {
            {
                std::lock_guard<std::mutex> lock(metadata_mutex);
                std::ifstream meta_file(metadata_path);
                json temp_metadata;
                meta_file >> temp_metadata;
                meta_file.close();

                for (const auto& chunk : temp_metadata["chunks"])
                {
                    if (chunk["hash"] == new_hash)
                    {
                        ref_count = chunk["ref_count"].get<int>();
                        break;
                    }
                }
            }
            updated_chunk_hashes.push_back({new_hash, ref_count});
            continue;
        }

        if (i < old_chunk_hashes.size())
        {
            std::string old_hash = old_chunk_hashes[i];
            bool chunk_still_referenced = false;
            {
                std::lock_guard<std::mutex> lock(metadata_mutex);
                for (const auto &entry : fs::directory_iterator(METADATA_DIR))
                {
                    std::ifstream meta_file(entry.path());
                    if (!meta_file.is_open()) continue;
                    try
                    {
                        json other_metadata;
                        meta_file >> other_metadata;
                        meta_file.close();

                        if (other_metadata.contains("chunks"))
                        {
                            for (auto &chunk : other_metadata["chunks"])
                            {
                                if (chunk["hash"] == old_hash)
                                {
                                    int new_ref_count = chunk["ref_count"].get<int>() - 1;
                                    chunk["ref_count"] = new_ref_count;
                                    if (new_ref_count > 0)
                                    {
                                        chunk_still_referenced = true;
                                    }
                                    std::ofstream updated_meta_file(entry.path());
                                    if (updated_meta_file.is_open())
                                    {
                                        updated_meta_file << other_metadata.dump(4);
                                        updated_meta_file.close();
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    catch (const json::exception& e)
                    {
                        std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                        continue;
                    }
                }

                if (!chunk_still_referenced)
                {
                    std::string chunk_path = CHUNK_DIR + "/" + old_hash;
                    if (fs::exists(chunk_path))
                    {
                        fs::remove(chunk_path);
                        std::cout << "Deleted old chunk: " << chunk_path << "\n";
                    }
                }
                else
                {
                    std::cout << "Old chunk " << old_hash << " still referenced by another file\n";
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(metadata_mutex);
            for (const auto &entry : fs::directory_iterator(METADATA_DIR))
            {
                std::ifstream meta_file(entry.path());
                if (!meta_file.is_open()) continue;
                try
                {
                    json other_metadata;
                    meta_file >> other_metadata;
                    meta_file.close();

                    if (other_metadata.contains("chunks"))
                    {
                        for (auto &chunk : other_metadata["chunks"])
                        {
                            if (chunk["hash"] == new_hash)
                            {
                                ref_count = chunk["ref_count"].get<int>() + 1;
                                chunk["ref_count"] = ref_count;
                                std::ofstream updated_meta_file(entry.path());
                                if (updated_meta_file.is_open())
                                {
                                    updated_meta_file << other_metadata.dump(4);
                                    updated_meta_file.close();
                                }
                                break;
                            }
                        }
                    }
                }
                catch (const json::exception& e)
                {
                    std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                    continue;
                }
            }

            std::string chunk_path = CHUNK_DIR + "/" + new_hash;
            if (!fs::exists(chunk_path))
            {
                std::ofstream chunk_file(chunk_path, std::ios::binary);
                if (!chunk_file.is_open())
                {
                    throw std::runtime_error("Failed to write chunk: " + chunk_path);
                }
                chunk_file.write(chunk_data.data(), chunk_data.size());
                chunk_file.close();
                std::cout << "Saved new chunk: " << chunk_path << "\n";
            }
        }
        updated_chunk_hashes.push_back({new_hash, ref_count});
    }

    for (size_t i = new_chunk_hashes.size(); i < old_chunk_hashes.size(); ++i)
    {
        std::string old_hash = old_chunk_hashes[i];
        bool chunk_still_referenced = false;
        {
            std::lock_guard<std::mutex> lock(metadata_mutex);
            for (const auto &entry : fs::directory_iterator(METADATA_DIR))
            {
                std::ifstream meta_file(entry.path());
                if (!meta_file.is_open()) continue;
                try
                {
                    json other_metadata;
                    meta_file >> other_metadata;
                    meta_file.close();

                    if (other_metadata.contains("chunks"))
                    {
                        for (auto &chunk : other_metadata["chunks"])
                        {
                            if (chunk["hash"] == old_hash)
                            {
                                int new_ref_count = chunk["ref_count"].get<int>() - 1;
                                chunk["ref_count"] = new_ref_count;
                                if (new_ref_count > 0)
                                {
                                    chunk_still_referenced = true;
                                }
                                std::ofstream updated_meta_file(entry.path());
                                if (updated_meta_file.is_open())
                                {
                                    updated_meta_file << other_metadata.dump(4);
                                    updated_meta_file.close();
                                }
                                break;
                            }
                        }
                    }
                }
                catch (const json::exception& e)
                {
                    std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                    continue;
                }
            }

            if (!chunk_still_referenced)
            {
                std::string chunk_path = CHUNK_DIR + "/" + old_hash;
                if (fs::exists(chunk_path))
                {
                    fs::remove(chunk_path);
                    std::cout << "Deleted old chunk: " << chunk_path << "\n";
                }
            }
        }
    }

    json new_metadata;
    new_metadata["filename"] = old_filename;
    new_metadata["size"] = total_size;
    new_metadata["content_type"] = content_type;
    new_metadata["cid"] = new_cid;
    new_metadata["file_ref_count"] = file_ref_count;

    json chunks_array = json::array();
    for (const auto &[hash, ref_count] : updated_chunk_hashes)
    {
        chunks_array.push_back({
            {"hash", hash},
            {"ref_count", ref_count}
        });
    }
    new_metadata["chunks"] = chunks_array;

    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&now_c), "%Y-%m-%dT%H:%M:%SZ");
    new_metadata["created_at"] = ss.str();

    {
        std::lock_guard<std::mutex> lock(metadata_mutex);
        std::ofstream meta_file(metadata_path);
        if (!meta_file.is_open())
        {
            throw std::runtime_error("Failed to update metadata file: " + metadata_path);
        }
        meta_file << new_metadata.dump(4);
        meta_file.close();
    }

    std::cout << "Updated metadata file: " << metadata_path << "\n";
    return true;
}

std::vector<nlohmann::json> list_files_metadata()
{
    std::vector<nlohmann::json> metadata_list;
    std::lock_guard<std::mutex> lock(metadata_mutex);
    for (const auto &entry : fs::directory_iterator(METADATA_DIR))
    {
        if (entry.path().extension() == ".json")
        {
            std::ifstream meta_file(entry.path());
            if (!meta_file.is_open()) continue;
            try
            {
                json metadata;
                meta_file >> metadata;
                metadata_list.push_back(metadata);
            }
            catch (const json::exception& e)
            {
                std::cerr << "Failed to parse metadata file " << entry.path() << ": " << e.what() << "\n";
                continue;
            }
        }
    }
    return metadata_list;
}