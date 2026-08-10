// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Host Network Egress Firewall Manager (Wall 4A pfctl integration)

#pragma once

#include <string>
#include <vector>

namespace aarchgate {

class EgressFirewall {
public:
    EgressFirewall() = default;
    ~EgressFirewall();

    // Generates and enables macOS pfctl rules restricting outbound traffic strictly to npm registry during install
    bool enable_npm_scoped_isolation(const std::vector<std::string>& allowed_registries = {"registry.npmjs.org", "registry.yarnpkg.com"});
    
    // Disables isolation and restores host firewall state
    bool disable_isolation();

    bool is_active() const { return active_; }

private:
    bool active_{false};
    std::string rules_file_path_{"/tmp/aarchgate_pf.conf"};

    std::string build_pf_rules(const std::vector<std::string>& allowed_registries) const;
};

} // namespace aarchgate
