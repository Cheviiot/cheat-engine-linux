#include "bridge/engine_facade.hpp"

#include "ce-gtk/src/bridge.rs.h"
#include "core/version.hpp"
#include "platform/linux/linux_process.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace ce::bridge {

rust::String EngineFacade::version() const {
    return std::string(ce::version());
}

namespace {

constexpr std::uint32_t kMaxProcessPageSize = 512;
constexpr std::size_t kMaxProcessQuerySize = 256;

std::string ascii_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

} // namespace

rust::Vec<ProcessRow> EngineFacade::list_processes(rust::Str query,
                                                    std::uint32_t limit) const {
    std::string needle(query);
    if (needle.size() > kMaxProcessQuerySize)
        needle.resize(kMaxProcessQuerySize);
    needle = ascii_lower(std::move(needle));

    ce::os::LinuxProcessEnumerator enumerator;
    auto processes = enumerator.list();
    std::sort(processes.begin(), processes.end(), [](const auto& left, const auto& right) {
        auto leftName = ascii_lower(left.name);
        auto rightName = ascii_lower(right.name);
        if (leftName != rightName) return leftName < rightName;
        return left.pid < right.pid;
    });

    rust::Vec<ProcessRow> rows;
    const auto pageSize = std::min(limit, kMaxProcessPageSize);
    if (pageSize == 0) return rows;

    for (const auto& process : processes) {
        if (!needle.empty()) {
            auto searchable = ascii_lower(process.name + "\n" + process.path);
            if (searchable.find(needle) == std::string::npos) continue;
        }

        rows.push_back(ProcessRow{
            .pid = static_cast<std::int32_t>(process.pid),
            .name = process.name,
            .path = process.path,
            .sandboxed = process.sandboxed,
        });
        if (rows.size() >= pageSize) break;
    }
    return rows;
}

std::unique_ptr<EngineFacade> create_engine_facade() {
    return std::make_unique<EngineFacade>();
}

} // namespace ce::bridge
