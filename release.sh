#!/usr/bin/env bash
#
# Cut a full release from the current commit, end to end:
#   1. requires a clean working tree;
#   2. refuses to run if there are no code changes since the last release tag;
#   3. bumps versionCode (+1) and versionName (patch +1);
#   4. builds the signed release APK;
#   5. commits, creates an annotated versioned tag and pushes both to origin;
#   6. publishes the GitHub Release with the artifact and SHA256SUMS.txt.
#
# Usage:
#   ./release.sh
#
# Override the toolchain by exporting JAVA_HOME / ANDROID_HOME beforehand.
#
set -euo pipefail

cd "$(dirname "$0")"

TITLE="Encrypt"
VERSION_FILE="app/build.gradle.kts"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
REPO="$(printf '%s' "$ORIGIN_URL" | sed -E 's#(git@|https://)github\.com[:/]##; s#\.git$##')"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export ANDROID_HOME="${ANDROID_HOME:-/home/reimen/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

die() { echo "error: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------------
[ "$BRANCH" != "HEAD" ] || die "detached HEAD; check out a branch first"
command -v gh >/dev/null || die "GitHub CLI (gh) not found"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"
[ -n "$REPO" ] || die "could not determine GitHub repo from origin remote ($ORIGIN_URL)"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean; commit or stash your changes first"
[ -x "$JAVA_HOME/bin/java" ] || die "JDK not found at JAVA_HOME=$JAVA_HOME"


# ---------------------------------------------------------------------------
# Current version: the higher of the version file and the last release tag, so a
# release never moves a published version backwards. The new tag keeps the
# prefix the repo already uses (v7.2.2, V1.0.0 or plain 1.0.1).
# ---------------------------------------------------------------------------
if [ -n "$VERSION_FILE" ]; then
    [ -f "$VERSION_FILE" ] || die "$VERSION_FILE not found (run from the repo root)"
    FILE_VERSION="$(sed -nE 's/.*versionName = "([^"]+)".*/\1/p' "$VERSION_FILE" | head -1)"
    [ -n "$FILE_VERSION" ] || die "could not read versionName from $VERSION_FILE"
    OLD_CODE="$(sed -nE 's/.*versionCode = ([0-9]+).*/\1/p' "$VERSION_FILE" | head -1)"
    [ -n "$OLD_CODE" ] || die "could not read versionCode from $VERSION_FILE"
else
    FILE_VERSION=""
fi

LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
if [ -n "$LAST_TAG" ]; then
    case "$LAST_TAG" in
        [vV]*) TAG_PREFIX="$(printf '%s' "$LAST_TAG" | cut -c1)" ;;
        *)     TAG_PREFIX="" ;;
    esac
    TAG_VERSION="$(printf '%s' "$LAST_TAG" | sed -E 's/^[vV]//')"
else
    TAG_PREFIX="v"
    TAG_VERSION=""
fi

printf '%s\n' "$FILE_VERSION" "$TAG_VERSION" | grep -E '^[0-9]+(\.[0-9]+)*$' | sort -V | tail -1 > "$OUT/base-version"
BASE_VERSION="$(cat "$OUT/base-version")"
[ -n "$BASE_VERSION" ] || die "no version found in ${VERSION_FILE:-the tree} or in any git tag"

NEW_VERSION="$(printf '%s' "$BASE_VERSION" | awk -F. '{
    v1 = $1 + 0; v2 = $2 + 0; v3 = ($3 == "" ? 0 : $3 + 0);
    printf "%d.%d.%d", v1, v2, v3 + 1
}')"
NEW_TAG="$TAG_PREFIX$NEW_VERSION"
echo "Release $BASE_VERSION -> $NEW_VERSION (tag $NEW_TAG) (build $((OLD_CODE + 1)))"
git rev-parse -q --verify "refs/tags/$NEW_TAG" >/dev/null && die "tag $NEW_TAG already exists"

# ---------------------------------------------------------------------------
# Refuse to release when only docs changed since the last tag.
# ---------------------------------------------------------------------------
if [ -n "$LAST_TAG" ]; then
    if git diff --quiet "$LAST_TAG"..HEAD -- . \
        ':(exclude,glob)**/*.md' ':(exclude,glob)docs/**' \
        ':(exclude)LICENSE' ':(exclude).gitignore'; then
        die "no code changes since $LAST_TAG - nothing to release"
    fi
fi

# ---------------------------------------------------------------------------
# Bump the version, then build. A failed build restores the tree.
# ---------------------------------------------------------------------------
restore() { git checkout -- "$VERSION_FILE" 2>/dev/null || true; }

sed -i "s/versionCode = $OLD_CODE/versionCode = $((OLD_CODE + 1))/" "$VERSION_FILE"
sed -i "s/versionName = \"$FILE_VERSION\"/versionName = \"$NEW_VERSION\"/" "$VERSION_FILE"

echo "Building the signed release APK..."
./build_apk.sh || { restore; die "build failed"; }

ARTIFACT="$(ls app/build/outputs/apk/release/app-release.apk 2>/dev/null | head -1 || true)"
[ -n "$ARTIFACT" ] || { restore; die "release artifact not found (app/build/outputs/apk/release/app-release.apk)"; }

cp "$ARTIFACT" "$OUT/Encrypt-${NEW_VERSION}.apk"
( cd "$OUT" && rm -f base-version && sha256sum Encrypt-${NEW_VERSION}.apk > SHA256SUMS.txt )

# ---------------------------------------------------------------------------
# Commit the version bump.
# ---------------------------------------------------------------------------
git add "$VERSION_FILE"
git commit -m "chore(release): $NEW_TAG (build $((OLD_CODE + 1)))"

# ---------------------------------------------------------------------------
# Tag, push and publish (always target the origin repo, never upstream).
# ---------------------------------------------------------------------------
git tag -a "$NEW_TAG" -m "$TITLE $NEW_VERSION"
git push origin "$BRANCH"
git push origin "$NEW_TAG"

if gh release view "$NEW_TAG" --repo "$REPO" >/dev/null 2>&1; then
    gh release upload "$NEW_TAG" "$OUT"/* --repo "$REPO" --clobber
else
    gh release create "$NEW_TAG" "$OUT"/* --repo "$REPO" \
        --title "$TITLE $NEW_VERSION" --generate-notes
fi

echo "Done: $NEW_TAG released (build $NEW_VERSION)."
