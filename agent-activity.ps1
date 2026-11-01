$script = Join-Path $PSScriptRoot 'agent-activity.py'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    [Console]::Error.WriteLine("agent-activity.py was not found next to this script ($PSScriptRoot).")
    exit 1
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$system = $me.User.Value -eq 'S-1-5-18'
$strict = $system -or (New-Object Security.Principal.WindowsPrincipal $me).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0',
             'S-1-5-80-956008885-3418522649-1831038044-1850242615-2271714194')
$refused = @()

function Test-AdminOnly([string]$path) {
    try {
        $sid = [Security.Principal.SecurityIdentifier]
        $acl = Get-Acl -LiteralPath $path
        if ($trusted -notcontains $acl.GetOwner($sid).Value) { return $false }
        foreach ($rule in $acl.GetAccessRules($true, $true, $sid)) {
            if ($rule.AccessControlType -eq 'Allow' -and ([int64]$rule.FileSystemRights -band 0x500D0156) -and
                    $trusted -notcontains $rule.IdentityReference.Value) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

if ($strict -and -not ((Test-AdminOnly $PSScriptRoot) -and (Test-AdminOnly $script))) {
    [Console]::Error.WriteLine('As an administrator or SYSTEM, agent-activity.py is run only from a folder no one but ' +
                               "SYSTEM, Administrators and TrustedInstaller can change, and others can change $PSScriptRoot.")
    exit 1
}

function Test-Python([string]$exe, [string[]]$pre) {
    if ($strict) {
        $dir = Split-Path -Parent $exe
        $site = Join-Path $dir 'Lib\site-packages'
        $paths = @($dir, $exe, (Join-Path $dir 'Lib'), (Join-Path $dir 'DLLs'), $site) + @(
            Get-ChildItem -LiteralPath $dir -Filter '*.dll' -Force -ErrorAction SilentlyContinue | ForEach-Object FullName) + @(
            Get-ChildItem -LiteralPath $site -Filter '*.pth' -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
        foreach ($p in $paths) {
            if (-not (Test-AdminOnly $p)) {
                $script:refused += $p
                return $false
            }
        }
    }
    try {
        & $exe @pre -I -c 'import sys; sys.exit(sys.version_info < (3, 9))' | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

$candidates = @()
$launchers = if ($system) { @(Join-Path $env:SystemRoot 'py.exe') } else {
    @(Get-Command py.exe -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
}
foreach ($py in @($launchers | Where-Object { $_ -notlike '*\WindowsApps\*' })) {
    if (-not $strict) {
        $candidates += , @($py, '-3')
    } elseif ((Test-Path -LiteralPath $py -PathType Leaf) -and (Test-AdminOnly $py) -and
              (Test-AdminOnly (Split-Path -Parent $py))) {
        foreach ($line in @(& $py -0p 2>$null)) {
            if ($line -match '([A-Za-z]:\\.+?\.exe)\s*$') { $candidates += , @($Matches[1]) }
        }
    } elseif (Test-Path -LiteralPath $py) {
        $refused += $py
    }
}
if (-not $system) {
    foreach ($c in @(Get-Command python.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
        if ($c.Source -notlike '*\WindowsApps\*') { $candidates += , @($c.Source) }
    }
}
$roots = @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)})
if ($env:LOCALAPPDATA -and -not $system) { $roots += Join-Path $env:LOCALAPPDATA 'Programs\Python' }
foreach ($root in ($roots | Where-Object { $_ } | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $root -Filter 'Python3*' -Directory -ErrorAction SilentlyContinue |
        Sort-Object { [int]($_.Name -replace '^Python(\d+).*$', '$1') } -Descending |
        ForEach-Object {
            $exe = Join-Path $_.FullName 'python.exe'
            if (Test-Path -LiteralPath $exe -PathType Leaf) { $candidates += , @($exe) }
        }
}

foreach ($c in $candidates) {
    $pre = @($c | Select-Object -Skip 1)
    if (Test-Python $c[0] $pre) {
        & $c[0] @pre -I $script @args
        exit $LASTEXITCODE
    }
}
if ($refused) {
    [Console]::Error.WriteLine('As an administrator or SYSTEM, a Python is run only if no one but SYSTEM, Administrators ' +
                               "and TrustedInstaller can change it, and others can change $(($refused | Select-Object -Unique) -join ', '). Install Python " +
                               'for all users, to the default folder under Program Files, and run this again.')
    exit 1
}
[Console]::Error.WriteLine('Python 3.9 or later was not found. Install it from https://www.python.org/downloads/windows/ ' +
                           'for all users and run this again.')
exit 1
