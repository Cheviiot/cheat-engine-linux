#pragma once

#include <string_view>

namespace ce {

/// The libcecore semantic version compiled into this build.
std::string_view version() noexcept;

} // namespace ce
