#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_DIR_NAME="ghidra-mcp"

usage() {
	cat <<'EOF'
Usage: ./install.sh [GHIDRA_INSTALL_DIR]

Builds and installs the extension into Ghidra's in-tree extension directory,
overwriting any existing ghidra-mcp install.

Environment:
  GHIDRA_INSTALL_DIR      Absolute path to the Ghidra installation.
  GHIDRA_USER_DIR         Optional per-user Ghidra settings directory override.
  GHIDRA_EXTENSIONS_DIR   Optional final Extensions directory override.
  SKIP_BUILD              Set to 1 to install the newest existing dist zip.
EOF
}

find_ghidra_install() {
	if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]]; then
		printf '%s\n' "$GHIDRA_INSTALL_DIR"
		return 0
	fi

	local candidates=()
	local pattern
	for pattern in \
		"$HOME"/ghidra_*_PUBLIC \
		"$HOME"/Applications/ghidra_*_PUBLIC \
		/Applications/ghidra_*_PUBLIC \
		/opt/ghidra_*_PUBLIC
	do
		local candidate
		for candidate in $pattern; do
			[[ -d "$candidate" ]] || continue
			candidates+=("$candidate")
		done
	done

	if ((${#candidates[@]} == 0)); then
		return 1
	fi

	printf '%s\n' "${candidates[@]}" | LC_ALL=C sort -V | tail -n 1
}

latest_extension_zip() {
	local newest=""
	local candidate

	while IFS= read -r -d '' candidate; do
		if [[ -z "$newest" || "$candidate" -nt "$newest" ]]; then
			newest="$candidate"
		fi
	done < <(find "$SCRIPT_DIR/dist" -maxdepth 1 -type f -name "ghidra_*_${EXTENSION_DIR_NAME}.zip" -print0 2>/dev/null)

	if [[ -z "$newest" ]]; then
		return 1
	fi

	printf '%s\n' "$newest"
}

first_arg="${1:-}"
if [[ "$first_arg" == "-h" || "$first_arg" == "--help" ]]; then
	usage
	exit 0
fi

if (($# > 1)); then
	usage >&2
	exit 2
fi

ghidra_dir=""
if [[ -n "$first_arg" ]]; then
	ghidra_dir="$first_arg"
else
	ghidra_dir="$(find_ghidra_install)" || {
		echo "Unable to locate a Ghidra installation. Set GHIDRA_INSTALL_DIR or pass the path explicitly." >&2
		exit 1
	}
fi

if [[ ! -f "$ghidra_dir/support/buildExtension.gradle" ]]; then
	echo "Invalid Ghidra installation: $ghidra_dir" >&2
	exit 1
fi

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
	"$SCRIPT_DIR/build.sh" "$ghidra_dir"
fi

zip_file="$(latest_extension_zip)" || {
	echo "No extension zip found in $SCRIPT_DIR/dist. Run ./build.sh first or unset SKIP_BUILD." >&2
	exit 1
}

if ! unzip -Z1 "$zip_file" "$EXTENSION_DIR_NAME/*" >/dev/null 2>&1; then
	echo "Unexpected extension zip layout: $zip_file" >&2
	echo "Expected a top-level $EXTENSION_DIR_NAME/ directory." >&2
	exit 1
fi

ghidra_user_dir=""
install_scope="Ghidra install tree"
if [[ -n "${GHIDRA_EXTENSIONS_DIR:-}" ]]; then
	extensions_dir="$GHIDRA_EXTENSIONS_DIR"
	install_scope="custom Extensions directory"
elif [[ -n "${GHIDRA_USER_DIR:-}" ]]; then
	ghidra_user_dir="$GHIDRA_USER_DIR"
	extensions_dir="$ghidra_user_dir/Extensions"
	install_scope="Ghidra user dir"
else
	extensions_dir="$ghidra_dir/Ghidra/Extensions"
fi

if [[ -z "$extensions_dir" || "$extensions_dir" == "/" ]]; then
	echo "Refusing to install into unsafe Extensions directory: ${extensions_dir:-<empty>}" >&2
	exit 1
fi

target_dir="$extensions_dir/$EXTENSION_DIR_NAME"

mkdir -p "$extensions_dir"

echo "Using Ghidra: $ghidra_dir"
echo "Install scope: $install_scope"
if [[ -n "$ghidra_user_dir" ]]; then
	echo "Using Ghidra user dir: $ghidra_user_dir"
fi
echo "Using Extensions dir: $extensions_dir"
echo "Installing: $zip_file"
echo "Target: $target_dir"

if [[ -e "$target_dir" || -L "$target_dir" ]]; then
	rm -rf "$target_dir"
fi

unzip -q "$zip_file" "$EXTENSION_DIR_NAME/*" -d "$extensions_dir"

echo "Installed extension folder: $target_dir"
echo "Restart Ghidra to load the updated extension."
