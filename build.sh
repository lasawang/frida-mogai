#!/bin/bash
#
# Frida 魔改自动化编译脚本
# 用法: ./build.sh [frida版本号]
# 示例: ./build.sh 16.5.2
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
FRIDA_VERSION="${1:-16.5.2}"
FRIDA_SRC="${BUILD_DIR}/frida-${FRIDA_VERSION}"
OUTPUT_DIR="${BUILD_DIR}/output"
PATCHES_RANDOMIZED="${BUILD_DIR}/patches_randomized"

# 编译目标架构（可按需修改）
TARGETS="android-arm64"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

check_deps() {
    log_info "Checking dependencies..."
    local missing=()

    for cmd in git python3 node npm meson ninja; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo "Install them before running this script."
        exit 1
    fi

    if ! python3 -c "import secrets" 2>/dev/null; then
        log_error "Python 3.6+ required (secrets module)"
        exit 1
    fi

    log_info "All dependencies satisfied."
}

clone_frida() {
    if [ -d "${FRIDA_SRC}" ]; then
        log_warn "Frida source already exists at ${FRIDA_SRC}"
        read -p "Re-use existing source? [Y/n] " choice
        if [[ "$choice" =~ ^[Nn] ]]; then
            rm -rf "${FRIDA_SRC}"
        else
            return 0
        fi
    fi

    log_info "Cloning frida ${FRIDA_VERSION}..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    git clone --recurse-submodules --depth 1 \
        --branch "${FRIDA_VERSION}" \
        https://github.com/frida/frida.git "frida-${FRIDA_VERSION}"

    log_info "Clone complete."
}

randomize_patches() {
    log_info "Randomizing patches..."
    cd "${SCRIPT_DIR}"
    python3 randomize.py

    if [ ! -d "${PATCHES_RANDOMIZED}" ]; then
        log_error "Randomized patches not found at ${PATCHES_RANDOMIZED}"
        exit 1
    fi

    log_info "Patches randomized successfully."
}

apply_patches() {
    log_info "Applying patches to frida-core..."

    local core_patches="${PATCHES_RANDOMIZED}/frida-core"
    local gum_patches="${PATCHES_RANDOMIZED}/frida-gum"

    if [ -d "$core_patches" ]; then
        cd "${FRIDA_SRC}/subprojects/frida-core"
        for patch in "${core_patches}"/*.patch; do
            if [ -f "$patch" ]; then
                log_info "  Applying $(basename "$patch")..."
                git apply --check "$patch" 2>/dev/null && \
                    git apply "$patch" || {
                        log_warn "  Failed to apply $(basename "$patch"), trying with 3-way merge..."
                        git apply --3way "$patch" || {
                            log_error "  Cannot apply $(basename "$patch")"
                            exit 1
                        }
                    }
            fi
        done
    fi

    if [ -d "$gum_patches" ]; then
        log_info "Applying patches to frida-gum..."
        cd "${FRIDA_SRC}/subprojects/frida-gum"
        for patch in "${gum_patches}"/*.patch; do
            if [ -f "$patch" ]; then
                log_info "  Applying $(basename "$patch")..."
                git apply --check "$patch" 2>/dev/null && \
                    git apply "$patch" || {
                        log_warn "  Failed to apply $(basename "$patch"), trying with 3-way merge..."
                        git apply --3way "$patch" || {
                            log_error "  Cannot apply $(basename "$patch")"
                            exit 1
                        }
                    }
            fi
        done
    fi

    log_info "All patches applied."
}

build_frida() {
    log_info "Building frida for ${TARGETS}..."
    cd "${FRIDA_SRC}"

    # 编译 frida-server
    log_info "Building frida-server..."
    make core-${TARGETS}

    # 编译 frida-gadget
    log_info "Building frida-gadget..."
    make gum-${TARGETS}

    log_info "Build complete."
}

collect_output() {
    log_info "Collecting build artifacts..."
    mkdir -p "${OUTPUT_DIR}"

    local arch
    case "${TARGETS}" in
        android-arm64) arch="arm64" ;;
        android-arm)   arch="arm" ;;
        android-x86_64) arch="x86_64" ;;
        android-x86)  arch="x86" ;;
        *) arch="${TARGETS}" ;;
    esac

    # frida-server
    local server_path="${FRIDA_SRC}/build/subprojects/frida-core/server/frida-server"
    if [ -f "$server_path" ]; then
        cp "$server_path" "${OUTPUT_DIR}/hlserver-${arch}"
        log_info "  frida-server => ${OUTPUT_DIR}/hlserver-${arch}"
    else
        log_warn "  frida-server binary not found at expected path"
        log_warn "  Searching..."
        find "${FRIDA_SRC}/build" -name "frida-server" -type f 2>/dev/null | head -5
    fi

    # frida-gadget
    local gadget_path="${FRIDA_SRC}/build/subprojects/frida-core/lib/gadget/frida-gadget.so"
    if [ -f "$gadget_path" ]; then
        cp "$gadget_path" "${OUTPUT_DIR}/hlgadget-${arch}.so"
        log_info "  frida-gadget => ${OUTPUT_DIR}/hlgadget-${arch}.so"
    else
        log_warn "  frida-gadget binary not found at expected path"
        find "${FRIDA_SRC}/build" -name "frida-gadget*" -type f 2>/dev/null | head -5
    fi

    log_info "Artifacts collected in ${OUTPUT_DIR}/"
}

verify_output() {
    log_info "Verifying build artifacts..."
    local has_error=0

    for binary in "${OUTPUT_DIR}"/*; do
        if [ -f "$binary" ]; then
            local hits
            hits=$(strings "$binary" | grep -ic "frida" || true)
            if [ "$hits" -gt 0 ]; then
                log_warn "  $(basename "$binary"): found ${hits} 'frida' string references!"
                has_error=1
            else
                log_info "  $(basename "$binary"): clean (no 'frida' strings)"
            fi
        fi
    done

    if [ "$has_error" -eq 1 ]; then
        log_warn "Some binaries still contain 'frida' strings. Check patches."
    else
        log_info "All binaries pass string verification."
    fi
}

print_summary() {
    echo
    echo "============================================"
    echo "  Build Summary"
    echo "============================================"
    echo "  Frida Version: ${FRIDA_VERSION}"
    echo "  Target:        ${TARGETS}"
    echo "  Output:        ${OUTPUT_DIR}/"
    echo
    echo "  Manifest:      ${BUILD_DIR}/randomize_manifest.json"
    echo "============================================"
    echo
    echo "Usage:"
    echo "  # Push server to device"
    echo "  adb push ${OUTPUT_DIR}/hlserver-arm64 /data/local/tmp/hlserver"
    echo "  adb shell chmod 755 /data/local/tmp/hlserver"
    echo "  adb shell /data/local/tmp/hlserver -l 127.0.0.1:8899"
    echo
    echo "  # Or use gadget with ZygiskFrida"
    echo "  cp ${OUTPUT_DIR}/hlgadget-arm64.so /path/to/zygisk-module/lib/"
    echo
}

main() {
    echo
    log_info "=== Frida Anti-Detection Build System ==="
    log_info "Version: ${FRIDA_VERSION} | Target: ${TARGETS}"
    echo

    check_deps
    clone_frida
    randomize_patches
    apply_patches
    build_frida
    collect_output
    verify_output
    print_summary

    log_info "All done."
}

main "$@"
