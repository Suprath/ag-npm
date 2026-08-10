// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Host Network Egress Firewall Implementation

#include "host/egress_firewall.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>

namespace aarchgate {

EgressFirewall::~EgressFirewall() {
    if (active_) {
        disable_isolation();
    }
}

std::string EgressFirewall::build_pf_rules(const std::vector<std::string>& allowed_registries) const {
    std::stringstream ss;
    ss << "# AarchGate Egress Isolation Rules\n"
       << "block out proto tcp all\n"
       << "block out proto udp all\n"
       << "pass out proto udp to any port 53\n"; // Allow DNS for registry resolution

    for (const auto& reg : allowed_registries) {
        ss << "# Allow registry: " << reg << "\n"
           << "pass out proto tcp to " << reg << " port 443\n";
    }

    return ss.str();
}

bool EgressFirewall::enable_npm_scoped_isolation(const std::vector<std::string>& allowed_registries) {
    std::string rules = build_pf_rules(allowed_registries);
    std::ofstream out(rules_file_path_);
    if (!out.is_open()) return false;
    out << rules;
    out.close();

    active_ = true;
    return true;
}

bool EgressFirewall::disable_isolation() {
    if (!active_) return true;
    std::remove(rules_file_path_.c_str());
    active_ = false;
    return true;
}

} // namespace aarchgate
