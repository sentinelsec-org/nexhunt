#!/bin/bash
# Publish a new NexHunt release to GitHub Releases.
#
# Usage: bash tools/release.sh [--dry-run] [--skip-build] [--skip-obfuscate]
# Run from the nexhunt-prod root on the developer's machine.
# Requires: gh (GitHub CLI), authenticated to sentinelsec-org/nexhunt repo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
DRY_RUN=0
SKIP_BUILD=0
SKIP_OBF=""

for arg in "$@"; do
  case "$arg" in
    --dry-run)         DRY_RUN=1 ;;
    --skip-build)      SKIP_BUILD=1 ;;
    --skip-obfuscate)  SKIP_OBF="--skip-obfuscate" ;;
  esac
done

VERSION="$(python3 -c "import sys; sys.path.insert(0,'$ROOT/backend'); from nexhunt.version import __version__; print(__version__)")"
TAG="v${VERSION}"
ARCHIVE="nexhunt-${VERSION}.tar.gz"
DEB_ASSET=""

ok()   { echo "  [ok] $1"; }
step() { echo; echo "==> $1"; }
die()  { echo "ERROR: $1" >&2; exit 1; }

if [ "$DRY_RUN" -eq 0 ]; then
  command -v gh &>/dev/null || die "gh CLI not found. Install from https://cli.github.com"
  gh auth status &>/dev/null || die "Not authenticated with gh. Run: gh auth login"
fi

step "Checking version ${VERSION}"
if git tag --list | grep -qx "$TAG"; then
  die "Tag $TAG already exists. Bump the version in backend/nexhunt/version.py first."
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  step "Building"
  bash "$ROOT/tools/build-prod.sh" $SKIP_OBF
fi

[ -f "$DIST/$ARCHIVE" ] || die "Archive not found: $DIST/$ARCHIVE. Run build-prod.sh first."
[ -f "$DIST/SHA256SUMS" ] || die "SHA256SUMS not found in $DIST."
DEB_ASSET="$(find "$DIST" -maxdepth 1 -type f -name "nexhunt_${VERSION}_*.deb" | head -1 || true)"

step "Generating release notes"
NOTES_FILE="$(mktemp /tmp/relnotes.XXXXXX.md)"
cat > "$NOTES_FILE" <<NOTES
## NexHunt ${VERSION}

### What's new
- (add changes here before releasing)

### Installation
\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/sentinelsec-org/nexhunt/main/install.sh | sudo bash
\`\`\`

Or download the .deb or tarball manually from this release.

---
_NexHunt by [Sentinel Security](https://nexhunt.myshopify.com)_
NOTES

# Open editor if available
if [ -n "${EDITOR:-}" ] && [ "$DRY_RUN" -eq 0 ]; then
  "$EDITOR" "$NOTES_FILE"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  step "DRY RUN - would create:"
  echo "  Tag:     $TAG"
  echo "  Archive: $DIST/$ARCHIVE ($(du -sh "$DIST/$ARCHIVE" | cut -f1))"
  echo "  Sums:    $DIST/SHA256SUMS"
  [ -n "$DEB_ASSET" ] && echo "  Deb:     $DEB_ASSET ($(du -sh "$DEB_ASSET" | cut -f1))"
  cat "$NOTES_FILE"
  rm -f "$NOTES_FILE"
  exit 0
fi

step "Tagging ${TAG}"
git tag -a "$TAG" -m "NexHunt ${VERSION}"
git push origin "$TAG"
ok "Tag pushed"

step "Creating GitHub Release"
ASSETS=("$DIST/$ARCHIVE" "$DIST/SHA256SUMS")
[ -n "$DEB_ASSET" ] && ASSETS+=("$DEB_ASSET")
gh release create "$TAG" \
  --title "NexHunt ${VERSION}" \
  --notes-file "$NOTES_FILE" \
  "${ASSETS[@]}"

rm -f "$NOTES_FILE"
ok "Release published: https://github.com/sentinelsec-org/nexhunt/releases/tag/${TAG}"

echo
echo "Release ${VERSION} is live. Clients will see the update on next check."
