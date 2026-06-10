# convert_symlinks_to_junctions.ps1
#
# Converts NTFS symlinks created by npm workspaces into junction points so
# that native Windows applications can traverse them without requiring
# SeCreateSymbolicLinkPrivilege.
#
# Works for both scoped (@scope/pkg) and unscoped workspace packages.
#
# Root cause: npm running inside WSL creates POSIX symlinks that land as NTFS
# symlinks on the Windows side regardless of Developer Mode settings. Native
# Windows applications cannot follow these -- only Windows junction points work.
# Run this script after any `npm install` executed from WSL or from a tool that
# runs in a Linux environment (e.g. a bash-based AI assistant tool).
#
# Usage (from the repo root):
#   PowerShell -ExecutionPolicy Bypass -File scripts\convert_symlinks_to_junctions.ps1
#
# Safe to run at any time -- already-correct junctions are skipped.

# Resolve the repo root relative to this script's location (scripts/ is one level down)
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

Write-Host "Repo root: $repoRoot"

if (-not (Test-Path $repoRoot)) {
    Write-Error "Repo root not found at: $repoRoot"
    exit 1
}

$totalFixed   = 0
$totalOk      = 0
$totalSkipped = 0
$totalErrors  = 0

function Convert-WorkspaceSymlinks {
    param (
        [string]$RepoPath
    )

    $repoName = Split-Path $RepoPath -Leaf
    $nm = Join-Path $RepoPath "node_modules"

    if (-not (Test-Path $nm)) {
        Write-Host "  (node_modules not found -- run npm install first)"
        return
    }

    # Read workspaces globs from package.json
    $pkgJson = Join-Path $RepoPath "package.json"
    if (-not (Test-Path $pkgJson)) { return }

    $pkg = Get-Content $pkgJson -Raw | ConvertFrom-Json
    $wsPatterns = $pkg.workspaces
    if (-not $wsPatterns) {
        Write-Host "  (no workspaces defined in package.json)"
        return
    }

    Write-Host ""
    Write-Host "=== $repoName ==="

    # Resolve all workspace package directories from the glob patterns.
    # npm workspace patterns are relative to the repo root.
    $workspaceDirs = @()
    foreach ($pattern in $wsPatterns) {
        if ($pattern -match '\*') {
            # Glob pattern (e.g. "packages/*") -- strip wildcard and collect children
            $glob = $pattern -replace '/\*\*$','' -replace '/\*$',''
            $resolved = Join-Path $RepoPath $glob
            if (Test-Path $resolved) {
                $workspaceDirs += Get-ChildItem -Path $resolved -Directory
            }
        } else {
            # Direct path to a single package
            $resolved = Join-Path $RepoPath $pattern
            if (Test-Path $resolved) {
                $workspaceDirs += Get-Item $resolved
            }
        }
    }

    if ($workspaceDirs.Count -eq 0) {
        Write-Host "  (no workspace package dirs resolved)"
        return
    }

    # Build a map of package name -> source directory from each workspace package.json
    $pkgNameToSrc = @{}
    foreach ($dir in $workspaceDirs) {
        $wsPkg = Join-Path $dir.FullName "package.json"
        if (Test-Path $wsPkg) {
            $wsMeta = Get-Content $wsPkg -Raw | ConvertFrom-Json
            if ($wsMeta.name) {
                $pkgNameToSrc[$wsMeta.name] = $dir.FullName
            }
        }
    }

    # For each workspace package, find its node_modules entry (may be scoped)
    foreach ($entry in $pkgNameToSrc.GetEnumerator()) {
        $pkgName = $entry.Key    # e.g. "@scope/package-name" or "package-name"
        $srcPath = $entry.Value

        # Compute the node_modules link path
        if ($pkgName -match '^(@[^/]+)/(.+)$') {
            $scope   = $Matches[1]
            $bare    = $Matches[2]
            $link    = Join-Path $nm "$scope\$bare"
        } else {
            $link = Join-Path $nm $pkgName
        }

        if (-not (Test-Path $link)) {
            Write-Host "  SKIP     $pkgName  -- not in node_modules (run npm install?)"
            $script:totalSkipped++
            continue
        }

        $item = Get-Item $link -Force

        if (-not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Write-Host "  SKIP     $pkgName  -- not a reparse point, leaving untouched"
            $script:totalSkipped++
            continue
        }

        if ($item.LinkType -eq "Junction") {
            Write-Host "  OK       $pkgName  -- already a junction"
            $script:totalOk++
            continue
        }

        # Symlink -- convert to junction
        Remove-Item $link -Force
        $result = cmd /c mklink /J $link $srcPath 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  FIXED    $pkgName  -- symlink -> junction"
            $script:totalFixed++
        } else {
            Write-Warning "  ERROR    $pkgName  -- mklink failed: $result"
            $script:totalErrors++
        }
    }
}

# Process this repo's workspace symlinks
Convert-WorkspaceSymlinks -RepoPath $repoRoot

Write-Host ""
Write-Host "------------------------------------"
Write-Host "Fixed: $totalFixed  OK: $totalOk  Skipped: $totalSkipped  Errors: $totalErrors"
Write-Host ""

if ($totalFixed -gt 0) {
    Write-Host "Restart any applications that were affected to pick up the changes."
}

if ($totalErrors -gt 0) {
    Write-Host "Some entries failed -- check output above."
    exit 1
}
