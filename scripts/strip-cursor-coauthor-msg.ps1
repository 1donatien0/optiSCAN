# SPDX-License-Identifier: GPL-3.0-or-later
# Lit un message de commit sur stdin, supprime Co-authored-by: Cursor, ├⌐crit sur stdout.
# Usage interne : git filter-branch --msg-filter "powershell -NoProfile -File scripts/strip-cursor-coauthor-msg.ps1"
$msg = [Console]::In.ReadToEnd()
$lines = $msg -split "`r?`n"
$filtered = $lines | Where-Object { $_ -notmatch '^\s*Co-authored-by:\s*Cursor\s*<' }
[Console]::Out.Write(($filtered -join "`n").TrimEnd() + "`n")
