#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
	cat <<'EOF'
Usage: ./build.sh [GHIDRA_INSTALL_DIR] [gradle-task...]

Examples:
  ./build.sh
  ./build.sh /Users/me/ghidra_12.1.2_PUBLIC
  ./build.sh clean buildExtension
  ./build.sh /Users/me/ghidra_12.1.2_PUBLIC clean buildExtension

Environment:
  GHIDRA_INSTALL_DIR   Absolute path to the Ghidra installation.
  GRADLE_CMD           Optional Gradle executable to use instead of Ghidra's bundled wrapper.
  GRADLE_USER_HOME     Optional Gradle cache directory. Defaults to .gradle next to this script.
  JAVA_HOME            JDK 21 location. Auto-detected when possible.
EOF
}

find_java_home() {
	local version="$1"

	if command -v /usr/libexec/java_home >/dev/null 2>&1; then
		local macos_java_home
		macos_java_home="$(/usr/libexec/java_home -v "$version" 2>/dev/null || true)"
		if [[ -x "$macos_java_home/bin/java" ]] && [[ "$(java_major_version "$macos_java_home/bin/java" || true)" == "$version" ]]; then
			printf '%s\n' "$macos_java_home"
			return 0
		fi
	fi

	local candidate
	for candidate in \
		"/opt/homebrew/opt/openjdk@$version/libexec/openjdk.jdk/Contents/Home" \
		"/usr/local/opt/openjdk@$version/libexec/openjdk.jdk/Contents/Home" \
		"/usr/lib/jvm/java-$version-openjdk" \
		"/usr/lib/jvm/java-$version-openjdk-amd64" \
		"/usr/lib/jvm/java-$version-openjdk-arm64" \
		"/usr/lib/jvm/temurin-$version-jdk" \
		"/usr/lib/jvm/temurin-$version-jdk-amd64" \
		"/usr/lib/jvm/temurin-$version-jdk-arm64"
	do
		if [[ -x "$candidate/bin/java" ]] && [[ "$(java_major_version "$candidate/bin/java" || true)" == "$version" ]]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done

	return 1
}

java_major_version() {
	local java_cmd="$1"
	local version_output
	version_output="$("$java_cmd" -version 2>&1)"

	if [[ "$version_output" =~ version[[:space:]]\"1\.([0-9]+) ]]; then
		printf '%s\n' "${BASH_REMATCH[1]}"
		return 0
	fi

	if [[ "$version_output" =~ version[[:space:]]\"([0-9]+) ]]; then
		printf '%s\n' "${BASH_REMATCH[1]}"
		return 0
	fi

	return 1
}

ensure_java_21() {
	local required_version=21
	local java_cmd
	local java_major

	if [[ -n "${JAVA_HOME:-}" ]]; then
		java_cmd="$JAVA_HOME/bin/java"
	else
		java_cmd="$(command -v java || true)"
	fi

	if [[ -n "$java_cmd" && -x "$java_cmd" ]]; then
		java_major="$(java_major_version "$java_cmd" || true)"
	fi

	if [[ "$java_major" != "$required_version" ]]; then
		local detected_java_home
		detected_java_home="$(find_java_home "$required_version" || true)"
		if [[ -n "$detected_java_home" ]]; then
			export JAVA_HOME="$detected_java_home"
			java_cmd="$JAVA_HOME/bin/java"
			java_major="$(java_major_version "$java_cmd" || true)"
		fi
	fi

	if [[ "$java_major" != "$required_version" ]]; then
		echo "Unsupported Java version: ${java_major:-unknown} (${java_cmd:-java})." >&2
		echo "Ghidra 12.1.2 extension builds must run on JDK 21, matching CI." >&2
		cat >&2 <<'EOF'
Install JDK 21 and set JAVA_HOME, for example:
  export JAVA_HOME=/path/to/jdk-21

Or on Homebrew:
  brew install openjdk@21
  export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
EOF
		exit 1
	fi

	echo "Using Java: $java_cmd"
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

first_arg="${1:-}"
ghidra_dir=""

if [[ "$first_arg" == "-h" || "$first_arg" == "--help" ]]; then
	usage
	exit 0
fi

if [[ -n "$first_arg" && -d "$first_arg" ]]; then
	ghidra_dir="$first_arg"
	shift
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

gradle_cmd="${GRADLE_CMD:-$ghidra_dir/support/gradle/gradlew}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SCRIPT_DIR/.gradle}"
ensure_java_21

if [[ ! -x "$gradle_cmd" ]]; then
	echo "Gradle command is not executable: $gradle_cmd" >&2
	exit 1
fi

if (($# == 0)); then
	set -- buildExtension
fi

echo "Using Ghidra: $ghidra_dir"
echo "Using Gradle: $gradle_cmd"
echo "Using Gradle user home: $GRADLE_USER_HOME"

exec "$gradle_cmd" -p "$SCRIPT_DIR" -PGHIDRA_INSTALL_DIR="$ghidra_dir" "$@"
