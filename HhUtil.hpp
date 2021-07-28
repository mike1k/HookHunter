#pragma once

struct ModuleInformation_t
{
    std::string module_path;
    std::uint64_t base_address;
    std::uint32_t module_size;
};

DWORD HhSearchForProcess(std::string_view process_name) noexcept;
bool HhFindModulesInProcess(HANDLE hProc, std::vector<ModuleInformation_t>& modules);
bool HhFindNamedModulesInProcess(HANDLE hProc, const std::vector<std::string>& names, std::vector<ModuleInformation_t>& modules);
