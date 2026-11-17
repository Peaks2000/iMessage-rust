#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    printf 'Usage: %s MACOS_10_11_SDK MACOS_11_3_SDK\n' "$0" >&2
    exit 2
fi

tool_dir=$(cd -- "$(dirname -- "$0")" && pwd)
build_dir=$(mktemp -d "$tool_dir/.macos-helper.XXXXXXXX")
trap 'rm -r -- "$build_dir"' EXIT

build() {
    local arch=$1 minimum=$2 sdk_version=$3 sdk_path=$4
    clang -target "$arch-apple-macos$minimum" -isysroot "$sdk_path" \
        -fobjc-arc -fblocks -Os -Wall -Werror \
        -c "$tool_dir/macos-device-helper.m" -o "$build_dir/$arch.o"
    ld64.lld -arch "$arch" -platform_version macos "$minimum" "$sdk_version" \
        -syslibroot "$sdk_path" -lSystem -framework Foundation -dead_strip -adhoc_codesign \
        "$build_dir/$arch.o" -o "$build_dir/$arch"
}

build x86_64 10.11 10.11 "$1"
build arm64 11.0 11.3 "$2"
llvm-lipo -create "$build_dir/x86_64" "$build_dir/arm64" -output "$build_dir/macos-device-helper"
chmod 644 "$build_dir/macos-device-helper"
mv -f -- "$build_dir/macos-device-helper" "$tool_dir/macos-device-helper"
