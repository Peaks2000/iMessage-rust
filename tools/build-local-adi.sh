#!/usr/bin/env bash
set -euo pipefail

# Pass a writable output directory. A checked-out apple-auth source directory
# can be supplied as the second argument for offline builds.
if (( $# < 1 || $# > 2 )); then
    echo "Usage: $0 OUTPUT_DIRECTORY [APPLE_AUTH_CHECKOUT]" >&2
    exit 2
fi
revision=98c862f7bebc8283a9b87f1578e703f0765dc81d
tool_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p -- "$1"
output="$(realpath -- "$1")"
scratch="$(mktemp -d)"
trap 'rm -r -- "$scratch"' EXIT
source_dir="${2:-$scratch/apple-auth}"
if (( $# == 1 )); then
    git clone --quiet --no-checkout https://github.com/apple-auth/apple-auth.git "$source_dir"
    git -C "$source_dir" checkout --quiet --detach "$revision"
fi
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$revision" ]] ||
    ! git -C "$source_dir" diff --quiet HEAD; then
    echo "Use the unmodified apple-auth checkout at $revision" >&2
    exit 1
fi
cmake -S "$source_dir" -B "$scratch/build" -DCMAKE_BUILD_TYPE=Release \
    -DAPPLE_AUTH_WITH_CLIENT=OFF -DAPPLE_AUTH_BUILD_EXAMPLES=OFF \
    -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build "$scratch/build" --parallel 4
"${CXX:-c++}" -O2 -std=c++20 -fPIC -shared -DAPPLE_AUTH_STATIC_DEFINE \
    -I"$source_dir/include" -I"$scratch/build/include" \
    "$tool_dir/local-adi.cpp" "$scratch/build/libapple_auth.a" \
    -lmbedcrypto -lmbedx509 -Wl,--exclude-libs,ALL -o "$scratch/libimessage-adi.so"
install -m 644 -- "$source_dir/LICENSE" "$output/apple-auth-LICENSE"
temp="$(mktemp "$output/.libimessage-adi.XXXXXX")"
install -m 755 -- "$scratch/libimessage-adi.so" "$temp"
mv -fT -- "$temp" "$output/libimessage-adi.so"
