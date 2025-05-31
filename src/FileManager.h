#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

extern const std::string CHUNK_DIR;
extern const std::string METADATA_DIR;
// extern std::mutex metadata_mutex;
void init_directories();
bool chunk_and_store_file(const std::string& filename, const std::string& content_type, const std::vector<char>& file_data, std::string& cid);
std::vector<char> read_and_reassemble_file(const std::string& identifier, bool is_cid = false);
bool delete_file(const std::string& identifier, bool is_cid = false);
bool update_file(const std::string& identifier, const std::string& content_type, const std::vector<char>& file_data, bool is_cid = false);
std::vector<nlohmann::json> list_files_metadata();

#endif // FILE_MANAGER_H