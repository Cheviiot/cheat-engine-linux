#pragma once

#include "rust/cxx.h"

#include <cstdint>
#include <memory>

namespace ce::bridge {

struct ProcessRow;

/// Stable, toolkit-neutral entry point exposed to the Rust frontend.
///
/// Keep implementation details and libcecore's template-heavy public surface on
/// the C++ side.  Only explicitly reviewed bridge-safe values belong here.
class EngineFacade {
public:
    EngineFacade() noexcept = default;

    rust::String version() const;
    rust::Vec<ProcessRow> list_processes(rust::Str query, std::uint32_t limit) const;
};

std::unique_ptr<EngineFacade> create_engine_facade();

} // namespace ce::bridge
