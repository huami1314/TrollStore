#!/usr/bin/env bash

set -Eeuo pipefail

root_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_directory="$root_directory/_build/ldid"
source_directory="$build_directory/source"
ldid_directory="$source_directory/ldid"
libplist_directory="$source_directory/libplist"
output_path="$root_directory/TrollStoreLite/Resources/ldid"
libcrypto_path="$root_directory/ChOma/external/ios/libcrypto.a"
entitlements_path="$root_directory/BuildTools/ldid.entitlements.plist"
ldid_repository="https://github.com/ProcursusTeam/ldid.git"
ldid_revision="af86971ae72ec3ed3d0a699107c4e882324c941b"
ldid_version="v2.1.5-procursus7-23-gaf86971"
libplist_repository="https://github.com/libimobiledevice/libplist.git"
libplist_revision="cf5897a71ea412ea2aeb1e2f6b5ea74d4fabfd8c"
libplist_version="2.7.0"

if [[ ! -f "$entitlements_path" ]]; then
	echo "error: missing ldid entitlements" >&2
	exit 1
fi

if [[ ! -f "$libcrypto_path" ]]; then
	echo "error: missing ChOma iOS libcrypto archive" >&2
	exit 1
fi

rm -rf "$build_directory"
mkdir -p "$source_directory"

checkout_source()
{
	local repository="$1"
	local revision="$2"
	local destination="$3"

	git clone --quiet --filter=blob:none --no-checkout "$repository" "$destination"
	git -C "$destination" checkout --quiet --detach "$revision"
}

checkout_source "$ldid_repository" "$ldid_revision" "$ldid_directory"
checkout_source "$libplist_repository" "$libplist_revision" "$libplist_directory"

sdk_path="$(xcrun --sdk iphoneos --show-sdk-path)"
common_c_flags=(
	-arch arm64
	-miphoneos-version-min=14.0
	-isysroot "$sdk_path"
	-Os
	-ffunction-sections
	-fdata-sections
	-I"$libplist_directory/include"
	-I"$libplist_directory/libcnary/include"
	-I"$libplist_directory/src"
	-DPACKAGE_VERSION=\"$libplist_version\"
	-D__LITTLE_ENDIAN__=1
	-DHAVE_STRDUP=1
	-DHAVE_STRNDUP=1
	-DHAVE_STRERROR=1
	-DHAVE_GMTIME_R=1
	-DHAVE_LOCALTIME_R=1
	-DHAVE_TIMEGM=1
	-DHAVE_STRPTIME=1
	-DHAVE_MEMMEM=1
	-DHAVE_TM_TM_GMTOFF=1
	-DHAVE_TM_TM_ZONE=1
)

libplist_sources=(
	"$libplist_directory/libcnary/node.c"
	"$libplist_directory/libcnary/node_list.c"
	"$libplist_directory/src/base64.c"
	"$libplist_directory/src/bytearray.c"
	"$libplist_directory/src/hashtable.c"
	"$libplist_directory/src/ptrarray.c"
	"$libplist_directory/src/time64.c"
	"$libplist_directory/src/xplist.c"
	"$libplist_directory/src/bplist.c"
	"$libplist_directory/src/jsmn.c"
	"$libplist_directory/src/jplist.c"
	"$libplist_directory/src/oplist.c"
	"$libplist_directory/src/out-default.c"
	"$libplist_directory/src/out-plutil.c"
	"$libplist_directory/src/out-limd.c"
	"$libplist_directory/src/plist.c"
)

libplist_objects=()
for source_index in "${!libplist_sources[@]}"; do
	object_path="$build_directory/libplist-$source_index.o"
	xcrun --sdk iphoneos clang "${common_c_flags[@]}" -c "${libplist_sources[$source_index]}" -o "$object_path"
	libplist_objects+=("$object_path")
done

libtool -static -o "$build_directory/libplist-2.0.a" "${libplist_objects[@]}"

read -r -a openssl_include_flags <<< "$(pkg-config --cflags-only-I libcrypto)"
xcrun --sdk iphoneos clang++ \
	-std=c++11 \
	-arch arm64 \
	-miphoneos-version-min=14.0 \
	-isysroot "$sdk_path" \
	-Os \
	-ffunction-sections \
	-fdata-sections \
	"${openssl_include_flags[@]}" \
	-I"$libplist_directory/include" \
	-DLDID_VERSION=\"$ldid_version\" \
	-c "$ldid_directory/ldid.cpp" \
	-o "$build_directory/ldid.o"

xcrun --sdk iphoneos clang++ \
	-arch arm64 \
	-miphoneos-version-min=14.0 \
	-isysroot "$sdk_path" \
	-Wl,-dead_strip \
	"$build_directory/ldid.o" \
	"$build_directory/libplist-2.0.a" \
	"$libcrypto_path" \
	-o "$build_directory/ldid"

xcrun --sdk iphoneos strip -S -x "$build_directory/ldid"
ldid -S"$entitlements_path" -Cadhoc "$build_directory/ldid"

if ! grep -aFq -- "-tTeamID" "$build_directory/ldid"; then
	echo "error: built ldid does not expose -tTeamID" >&2
	exit 1
fi

install -m 0755 "$build_directory/ldid" "$output_path"
