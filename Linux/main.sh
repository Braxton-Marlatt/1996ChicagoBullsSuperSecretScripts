#!/bin/bash
# main.sh — Linux Hardening Control Script

MODULE_DIR="./modules"
UTILS_DIR="./utils"

# Source shared functions if needed
source "$UTILS_DIR/common.sh"

show_help() {
    echo "Usage: $0 [option]"
    echo
    echo "Options:"
    echo "  --all                 Run all modules"
    echo "  --module <name>       Run a specific module (e.g., ssh_hardening)"
    echo "  --list                Show available modules"
    echo "  --help                Show this help message"
    echo
}

list_modules() {
    echo "Available modules:"
    for file in "$MODULE_DIR"/*.sh; do
        basename "$file" .sh
    done
}

run_module() {
    local module="$1"
    local file="$MODULE_DIR/$module.sh"
    if [[ -f "$file" ]]; then
        echo ">>> Running module: $module"
        source "$file"
        echo ">>> $module complete"
    else
        echo "Error: Module '$module' not found."
        exit 1
    fi
}

run_all() {
    for file in "$MODULE_DIR"/*.sh; do
        module_name=$(basename "$file" .sh)
        run_module "$module_name"
    done
}

# --- Argument parsing ---
case "$1" in
    --all)
        run_all
        ;;
    --module)
        [[ -z "$2" ]] && { echo "Error: missing module name"; exit 1; }
        run_module "$2"
        ;;
    --list)
        list_modules
        ;;
    --help|*)
        show_help
        ;;
esac
