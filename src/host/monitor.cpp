// (c) 2026 Suprath PS. All rights reserved.
// AarchGate: Real-Time Telemetry Monitor v3.0

#include <iostream>
#include <vector>
#include <map>
#include <queue>
#include <string>
#include <chrono>
#include <thread>
#include <csignal>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <ctime>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

#include "common/monitor_protocol.h"
#include "iceoryx_posh/runtime/posh_runtime.hpp"
#include "iceoryx_posh/popo/subscriber.hpp"

using namespace aarchgate;

// ── ANSI Terminal Control ─────────────────────────────────────────────────────
#define RESET       "\033[0m"
#define BOLD        "\033[1m"
#define DIM         "\033[2m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define MAGENTA     "\033[35m"
#define CYAN        "\033[36m"
#define WHITE       "\033[37m"
#define BG_RED      "\033[41m"
#define BG_YELLOW   "\033[43m"
#define BG_GREEN    "\033[42m"
#define CLEAR_SCR   "\033[2J\033[H"
#define HIDE_CURSOR "\033[?25l"
#define SHOW_CURSOR "\033[?25h"

// ── Disabled flag path ────────────────────────────────────────────────────────
static std::string disabled_flag_path() {
    const char* home = getenv("HOME");
    if (!home) home = "/tmp";
    return std::string(home) + "/.aarchgate/.disabled";
}

static bool is_protection_disabled() {
    std::ifstream f(disabled_flag_path());
    return f.good();
}

static bool set_protection_disabled(bool disable) {
    if (disable) {
        std::ofstream f(disabled_flag_path());
        return f.good();
    } else {
        return (std::remove(disabled_flag_path().c_str()) == 0);
    }
}

// ── Non-blocking keyboard input ───────────────────────────────────────────────
struct RawTerminal {
    termios orig{};
    RawTerminal() {
        tcgetattr(STDIN_FILENO, &orig);
        termios raw = orig;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN]  = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    }
    ~RawTerminal() { tcsetattr(STDIN_FILENO, TCSANOW, &orig); }
};

static char poll_keypress() {
    char c = 0;
    read(STDIN_FILENO, &c, 1);
    return c;
}

// ── Global state ──────────────────────────────────────────────────────────────
std::atomic<bool> g_stop{false};
std::atomic<bool> g_show_help{false};

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) g_stop = true;
}

// ── Data model ────────────────────────────────────────────────────────────────
struct ProcessNode {
    uint64_t pid;
    uint64_t ppid;
    std::string comm;
    std::string arg;
    bool is_preinstall;
    std::vector<uint64_t> children;
};

struct TelemetryModel {
    bool vm_running     = false;
    std::string vm_status_desc = "Offline";

    uint64_t total_execs    = 0;
    uint64_t total_opens    = 0;
    uint64_t total_connects = 0;
    uint64_t total_forks    = 0;
    uint64_t total_mte_traps = 0;
    uint64_t total_violations = 0;

    std::map<uint64_t, ProcessNode> processes;
    std::vector<uint64_t> root_pids;
    std::vector<MonitorEvent> logs;

    void add_event(const MonitorEvent& ev) {
        if (ev.event_type == EVENT_VM_STATE_CHANGE) {
            vm_running       = (ev.vm_running == 1);
            vm_status_desc   = ev.arg_str;
            return;
        }

        logs.push_back(ev);
        if (logs.size() > 30) logs.erase(logs.begin());

        if (ev.event_type == EVENT_EXEC)        total_execs++;
        else if (ev.event_type == EVENT_OPEN)   total_opens++;
        else if (ev.event_type == EVENT_CONNECT) total_connects++;
        else if (ev.event_type == EVENT_FORK)   total_forks++;
        else if (ev.event_type == EVENT_MTE_TRAP) total_mte_traps++;

        if (ev.is_sensitive  && ev.is_preinstall && ev.event_type == EVENT_OPEN)    total_violations++;
        if (ev.is_unauthorized && ev.is_preinstall && ev.event_type == EVENT_CONNECT) total_violations++;

        if (ev.event_type == EVENT_EXEC || ev.event_type == EVENT_FORK) {
            if (processes.find(ev.pid) == processes.end()) {
                ProcessNode node{};
                node.pid  = ev.pid;
                node.ppid = ev.ppid;
                node.comm = ev.comm;
                node.arg  = ev.arg_str;
                node.is_preinstall = (ev.is_preinstall == 1);
                processes[ev.pid] = node;
                if (ev.ppid != 0 && processes.find(ev.ppid) != processes.end())
                    processes[ev.ppid].children.push_back(ev.pid);
                else
                    root_pids.push_back(ev.pid);
            }
        }
    }
};

// ── Process tree rendering ────────────────────────────────────────────────────
void draw_process_node(const TelemetryModel& model, uint64_t pid, const std::string& prefix, bool is_last) {
    auto it = model.processes.find(pid);
    if (it == model.processes.end()) return;
    const auto& node = it->second;

    std::cout << prefix << (is_last ? "└── " : "├── ");
    if (node.is_preinstall) {
        std::cout << YELLOW << BOLD << node.comm << RESET
                  << " (PID: " << node.pid << ")" << RED << " [UNTRUSTED]" << RESET;
    } else {
        std::cout << GREEN << node.comm << RESET << " (PID: " << node.pid << ")";
    }
    if (!node.arg.empty() && node.arg != "fork")
        std::cout << " " << WHITE << "[" << node.arg << "]" << RESET;
    std::cout << "\n";

    std::string new_prefix = prefix + (is_last ? "    " : "│   ");
    for (size_t i = 0; i < node.children.size(); ++i)
        draw_process_node(model, node.children[i], new_prefix, i == node.children.size() - 1);
}

// ── Live clock helper ─────────────────────────────────────────────────────────
static std::string current_time_str() {
    auto now  = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

// ── Dashboard renderer ────────────────────────────────────────────────────────
void render_dashboard(const TelemetryModel& model) {
    bool disabled = is_protection_disabled();

    std::cout << CLEAR_SCR;

    // ── Header ────────────────────────────────────────────────────────────────
    std::cout << BOLD << CYAN
              << "================================================================================\n"
              << "                 AarchGate Zero-Trust Sandbox Monitor v3.0                      \n"
              << "================================================================================"
              << RESET << "\n";

    // ── Protection state banner ───────────────────────────────────────────────
    if (disabled) {
        std::cout << BG_YELLOW << BOLD
                  << "  ⚠  PROTECTION DISABLED — package installs are NOT sandboxed               "
                  << RESET << "\n"
                  << DIM << "  Press [E] to re-enable protection\n" << RESET;
    } else {
        std::cout << BG_GREEN << BOLD
                  << "  ✔  PROTECTION ENABLED — all package installs are sandboxed                "
                  << RESET << "\n"
                  << DIM << "  Press [D] to disable | [T] to toggle | [H] for help | [Q] to quit\n" << RESET;
    }

    // ── VM Lifecycle ──────────────────────────────────────────────────────────
    std::cout << "\n" << BOLD << "VM Lifecycle: " << RESET;
    if (disabled) {
        std::cout << DIM << "[BYPASSED] (Protection is disabled — VM not started)" << RESET << "\n";
    } else if (model.vm_running) {
        std::cout << GREEN << BOLD << "[RUNNING] " << RESET << "(" << model.vm_status_desc << ")\n";
    } else {
        bool killed = (model.total_violations > 0) ||
                      (model.vm_status_desc.find("Kill Switch") != std::string::npos);
        if (killed)
            std::cout << RED << BOLD << "[KILLED]  " << RESET << "(" << model.vm_status_desc << ")\n";
        else if (model.logs.empty() && model.total_execs == 0)
            std::cout << YELLOW << BOLD << "[WAITING] " << RESET << "(Waiting for aarchgate_daemon...)\n";
        else
            std::cout << WHITE << BOLD << "[OFFLINE] " << RESET << "(" << model.vm_status_desc << ")\n";
    }

    // ── Risk Score ────────────────────────────────────────────────────────────
    uint32_t risk = 0;
    if (model.total_violations > 0)
        risk = 80 + std::min(static_cast<uint32_t>(model.total_violations * 5), 20U);

    std::cout << BOLD << "Security Risk Score: " << RESET;
    if (disabled) {
        std::cout << YELLOW << BOLD << "N/A [MONITORING PAUSED]" << RESET;
    } else if (risk >= 80) {
        std::cout << RED << BOLD << risk << "/100 [CRITICAL THREAT DETECTED]" << RESET;
    } else if (risk >= 40) {
        std::cout << YELLOW << BOLD << risk << "/100 [SUSPICIOUS BEHAVIOUR]" << RESET;
    } else {
        std::cout << GREEN << BOLD << risk << "/100 [CLEAN WORKSPACE]" << RESET;
    }
    std::cout << "   " << DIM << current_time_str() << RESET << "\n";

    // ── Telemetry Statistics ──────────────────────────────────────────────────
    std::cout << BOLD << "\n[Telemetry Statistics]\n" << RESET;
    std::cout << "  Spawns (EXEC): " << BOLD << model.total_execs   << RESET
              << "   |   Forks: "    << BOLD << model.total_forks   << RESET
              << "   |   File Opens: " << BOLD << model.total_opens << RESET
              << "   |   Connections: " << BOLD << model.total_connects << RESET << "\n";
    std::cout << "  MTE Traps:     "
              << BOLD << (model.total_mte_traps > 0 ? RED : GREEN)
              << model.total_mte_traps << RESET
              << "   |   Violations: "
              << BOLD << (model.total_violations > 0 ? RED : GREEN)
              << model.total_violations << RESET << "\n";
    std::cout << "--------------------------------------------------------------------------------\n";

    // ── Process Tree ──────────────────────────────────────────────────────────
    std::cout << BOLD << "\n[Sandbox Process Tree Hierarchy]\n" << RESET;
    if (disabled) {
        std::cout << DIM << "  No sandbox active — protection is disabled.\n" << RESET;
    } else if (model.root_pids.empty()) {
        std::cout << "  No processes spawned in sandbox yet.\n";
    } else {
        for (size_t i = 0; i < model.root_pids.size(); ++i)
            draw_process_node(model, model.root_pids[i], "  ", i == model.root_pids.size() - 1);
    }
    std::cout << "\n--------------------------------------------------------------------------------\n";

    // ── Syscall Log ───────────────────────────────────────────────────────────
    std::cout << BOLD << "\n[Real-Time Intercepted Syscall Logs (Live Stream)]\n" << RESET;
    if (disabled) {
        std::cout << DIM << "  Monitoring paused. Press [E] to re-enable.\n" << RESET;
    } else if (model.logs.empty()) {
        std::cout << "  Awaiting syscall telemetry stream...\n";
    } else {
        for (const auto& log : model.logs) {
            std::string comm = std::string(log.comm).substr(0, 15);
            std::cout << "  ";

            if (log.event_type == EVENT_MTE_TRAP) {
                std::cout << BG_RED << BOLD << "[MTE TRAP]   " << RESET
                          << " " << RED << comm << RESET
                          << " violated hardware tags at " << RED << log.arg_str << RESET << "\n";
            } else if (log.is_sensitive && log.is_preinstall && log.event_type == EVENT_OPEN) {
                std::cout << RED << BOLD << "[BLOCKED OPEN]  " << RESET
                          << " preinstall " << RED << comm << RESET
                          << " tried to read: " << RED << log.arg_str << RESET << "\n";
            } else if (log.is_unauthorized && log.is_preinstall && log.event_type == EVENT_CONNECT) {
                std::cout << RED << BOLD << "[BLOCKED CONN]  " << RESET
                          << " preinstall " << RED << comm << RESET
                          << " exfil attempt: " << RED << log.arg_str << ":" << log.port << RESET << "\n";
            } else if (log.event_type == EVENT_EXEC) {
                std::cout << GREEN << BOLD << "[EXEC]   " << RESET
                          << " PID " << std::setw(5) << log.pid << " "
                          << BOLD << std::left << std::setw(15) << comm << RESET
                          << " -> " << log.arg_str << "\n";
            } else if (log.event_type == EVENT_FORK) {
                std::cout << YELLOW << "[FORK]   " << RESET
                          << " PID " << std::setw(5) << log.pid
                          << " (PPID " << log.ppid << ") "
                          << std::left << std::setw(15) << comm << "\n";
            } else if (log.event_type == EVENT_OPEN) {
                std::cout << CYAN << "[OPEN]   " << RESET
                          << " PID " << std::setw(5) << log.pid << " "
                          << std::left << std::setw(15) << comm
                          << " path: " << log.arg_str << "\n";
            } else if (log.event_type == EVENT_CONNECT) {
                std::string dest = log.arg_str;
                if (dest.empty() || dest == "other_connect") {
                    uint32_t ip = log.ip_address;
                    dest = std::to_string((ip >> 24) & 0xFF) + "." +
                           std::to_string((ip >> 16) & 0xFF) + "." +
                           std::to_string((ip >>  8) & 0xFF) + "." +
                           std::to_string( ip        & 0xFF);
                }
                std::cout << MAGENTA << "[CONNECT]" << RESET
                          << " PID " << std::setw(5) << log.pid << " "
                          << std::left << std::setw(15) << comm
                          << " -> " << dest << ":" << log.port << "\n";
            }
        }
    }

    // ── Help overlay ──────────────────────────────────────────────────────────
    if (g_show_help) {
        std::cout << "\n" << BOLD << CYAN
                  << "  ┌─────────────── Keyboard Shortcuts ───────────────┐\n"
                  << "  │  E  →  Enable protection                        │\n"
                  << "  │  D  →  Disable protection (confirms with Y)     │\n"
                  << "  │  T  →  Toggle protection on/off                 │\n"
                  << "  │  H  →  Show/hide this help panel                │\n"
                  << "  │  Q  →  Quit monitor (does not stop daemon)      │\n"
                  << "  └──────────────────────────────────────────────────┘\n"
                  << RESET;
    }

    // ── Footer ────────────────────────────────────────────────────────────────
    std::cout << "\n" << DIM
              << "  [E] Enable  [D] Disable  [T] Toggle  [H] Help  [Q] Quit"
              << RESET << "\n";
    std::cout << std::flush;
}

// ── Entry point ───────────────────────────────────────────────────────────────
int main() {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << HIDE_CURSOR << std::flush;
    RawTerminal raw_term;

    std::cout << "[AarchGate Monitor] Initializing shared-memory runtime..." << std::endl;

    try {
        iox::runtime::PoshRuntime::initRuntime("AARCHGATE_MONITOR");
    } catch (...) {
        std::cerr << "[AarchGate Monitor] ERROR: iox-roudi not running. Start with: iox-roudi\n";
        std::cout << SHOW_CURSOR;
        return 1;
    }

    iox::popo::Subscriber<MonitorEvent> subscriber({
        iox::capro::IdString_t{iox::TruncateToCapacity, "AarchGate"},
        iox::capro::IdString_t{iox::TruncateToCapacity, "Sandbox"},
        iox::capro::IdString_t{iox::TruncateToCapacity, "Telemetry"}
    });

    TelemetryModel model;
    std::cout << CLEAR_SCR << std::flush;
    render_dashboard(model);

    // Awaiting disable confirmation
    bool awaiting_disable_confirm = false;

    auto last_render = std::chrono::steady_clock::now();

    while (!g_stop) {
        // ── Keyboard handler ─────────────────────────────────────────────────
        char key = poll_keypress();
        if (key != 0) {
            switch (key) {
                case 'q': case 'Q':
                    g_stop = true;
                    break;
                case 'h': case 'H':
                    g_show_help = !g_show_help;
                    render_dashboard(model);
                    break;
                case 'e': case 'E':
                    set_protection_disabled(false);
                    awaiting_disable_confirm = false;
                    render_dashboard(model);
                    break;
                case 'd': case 'D':
                    if (!awaiting_disable_confirm) {
                        awaiting_disable_confirm = true;
                        std::cout << "\n" << YELLOW << BOLD
                                  << "  ⚠  Disable protection? Press [Y] to confirm or any other key to cancel."
                                  << RESET << "\n" << std::flush;
                    }
                    break;
                case 'y': case 'Y':
                    if (awaiting_disable_confirm) {
                        set_protection_disabled(true);
                        awaiting_disable_confirm = false;
                        render_dashboard(model);
                    }
                    break;
                case 't': case 'T':
                    if (is_protection_disabled())
                        set_protection_disabled(false);
                    else
                        set_protection_disabled(true);
                    awaiting_disable_confirm = false;
                    render_dashboard(model);
                    break;
                default:
                    if (awaiting_disable_confirm) {
                        awaiting_disable_confirm = false;
                        render_dashboard(model);
                    }
                    break;
            }
        }

        // ── IPC event consumer ───────────────────────────────────────────────
        bool updated = false;
        while (true) {
            auto result = subscriber.take();
            if (result.has_error()) break;
            model.add_event(*result.value());
            updated = true;
        }

        // ── Redraw every 500ms or on new events ──────────────────────────────
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_render).count();
        if (updated || elapsed >= 500) {
            render_dashboard(model);
            last_render = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::cout << SHOW_CURSOR << "\n[AarchGate Monitor] Exiting.\n";
    return 0;
}
