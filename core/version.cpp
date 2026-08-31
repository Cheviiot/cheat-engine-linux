#include "core/version.hpp"

namespace ce {

std::string_view version() noexcept {
    return CECORE_VERSION;
}

} // namespace ce
