# Set up a git remote for ZeroTrust-SOC-Lab.
#
# WRITTEN BUT NOT RUN. The agent that wrote it had lost the ability to execute
# anything, and pushing a repository is not something to hand over on faith.
# Everything below is something to read, check, and then run yourself.
#
# WHY THIS MATTERS MORE THAN ANY OPEN BUG
# --------------------------------------
# 43 commits exist on one disk. Every other problem in this project is
# reproducible from the repository; a disk failure is not, and it takes the
# history with it -- including the records of the bugs that were found and fixed,
# which is the most useful document in the repo.
#
# READ THIS BEFORE PUSHING
# ------------------------
# This repository contains, by design:
#
#   * credentials that are real, generated at apply time, and were committed
#     and then removed at least once. gitleaks caught one instance; git history
#     is append-only, so anything ever committed stays reachable.
#   * a working privilege-escalation path: sa-build-runner holds cluster-admin,
#     and attack/chain-purple-team.ps1 demonstrates the full chain end to end.
#   * deliberately vulnerable images, pinned by digest.
#
# That is the project. It is also exactly what an unauthorised reader wants. So:
#
#   *** PUSH TO A PRIVATE REPOSITORY. ***
#
# Do not make it public. Do not fork it to a public host. If you need a public
# demo, that is a different repository with the payloads removed, and removing
# them is a deliberate piece of work, not a squash commit.
#
# Before the first push
# ---------------------
#   git log --all --full-history -p -- secrets/ | less
#
# If a real credential is anywhere in that history, rotating it is cheaper than
# explaining it later. secrets/credentials.yaml is gitignored and
# credentials.example.yaml is the tracked placeholder; the risk is an accidental
# `git add -f` at some point in the past, not the current state.

# ---------------------------------------------------------------------------
# STEP 1 — create the private repository, then paste its URL here.
#
#   GitHub : https://github.com/new  ->  New repository -> Private
#   GitLab  : https://gitlab.com/new ->  New project     -> Private
#   Other  : any host you trust with this content
#
# Do NOT initialise it with a README, .gitignore or a licence. This repository
# already has all three, and an initialising commit on a remote is the single
# most common way to make the first push fail.
# ---------------------------------------------------------------------------

$remoteUrl = 'https://github.com/YOUR-ACCOUNT/YOUR-PRIVATE-REPO.git'   # <-- edit this

if ($remoteUrl -like '*YOUR-*') {
    Write-Host 'Edit $remoteUrl above first.' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# STEP 2 — add the remote and push.
#
# `git remote add` is local and reversible: `git remote remove origin` undoes it.
# The push is the part that matters, so the confirmation is here.
# ---------------------------------------------------------------------------

$root = 'D:\ZeroTrust-SOC-Lab'
Set-Location $root

$existing = (git remote)
if ($existing) {
    Write-Host "remotes already present:" -ForegroundColor Yellow
    Write-Host $existing
    Write-Host 'Nothing changed. Remove one first with: git remote remove <name>' -ForegroundColor Yellow
    exit 1
}

Write-Host 'about to add the remote and push 43 commits' -ForegroundColor Cyan
Write-Host "  $remoteUrl" -ForegroundColor White
Write-Host ''
$confirm = Read-Host 'Type PUSH-PRIVATE to confirm this repository is private and you want to push'
if ($confirm -cne 'PUSH-PRIVATE') {
    Write-Host 'not pushed. Nothing was changed.' -ForegroundColor Green
    exit 0
}

git remote add origin $remoteUrl
if ($LASTEXITCODE -ne 0) { throw 'git remote add failed' }

git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'push failed. The remote is still configured, so you can retry with:' -ForegroundColor Yellow
    Write-Host '  git push -u origin main' -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host 'pushed.' -ForegroundColor Green
git --no-pager log --oneline -3
Write-Host ''
Write-Host 'Now, while you are here: branch protection on main.' -ForegroundColor Cyan
Write-Host 'Settings -> Branches -> Add rule for main. Minimal and worth having:' -ForegroundColor DarkGray
Write-Host '  - require a pull request before merging      (1 approval)' -ForegroundColor DarkGray
Write-Host '  - require status checks to pass: "cluster-free test suites"' -ForegroundColor DarkGray
Write-Host '  - do not allow force pushes' -ForegroundColor DarkGray
Write-Host ''
Write-Host 'That last one matters more than it looks. Every commit in this repository' -ForegroundColor DarkGray
Write-Host 'was made with a gate that can fail, and a force push is the easiest way to' -ForegroundColor DarkGray
Write-Host 'throw that away without noticing.' -ForegroundColor DarkGray
