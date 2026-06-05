<#
.SYNOPSIS
Autopilot TPM Attestation readiness checker v0.24 with a WinForms GUI.

.DESCRIPTION
Checks the most common TPM attestation blockers for Windows Autopilot pre-provisioning.
No WMIC dependency.
Uses CIM, registry checks, scheduled tasks, TPM cmdlets, certificate chain inspection,
cmd-based certreq AIK validation, and optional local helper files.

Changes in v0.24 compared to v0.23:
- certreq -enrollaik SYSTEM relaunch: when certreq returns 0x80070542
  ERROR_BAD_IMPERSONATION_LEVEL from the user context, the tool now automatically
  relaunches certreq as SYSTEM via a one-shot scheduled task (Invoke-AikCertreqAsSystem).
  This gives CertEnroll.dll::EnrollForAIKCertificate the impersonation level it needs,
  producing a real AIK test result (cert or genuine failure) instead of an ambiguous
  context error. The temp task and output files are cleaned up after each run.
- If the SYSTEM relaunch also returns the impersonation error (genuinely unexpected),
  that is surfaced as WARN with explicit guidance rather than silently swallowed.
- Show-AikTestOutputWindow now accepts -ImpersonationContext to suppress the misleading
  'AIK URL(s): none detected' line when certreq never reached the CA lookup stage.
- Replaced Test-AikBadImpersonationOutput with Test-IsAikImpersonationError (predicate
  only, no side-effects) to keep the detection logic separate from the retry logic.
- Export report button now generates a self-contained HTML report (New-HtmlReport /
  Export-HtmlReport) and opens it in the default browser. CSV and log are still
  written alongside it as companion files.
- Re-added OOBEAADV10 / Intune portal content check (portal.manage.microsoft.com HTTP response)
  as a dedicated connectivity row. Inspired by test-managemicrosoft from the v0.11 script.
- Re-added azure.net as an endpoint in the connectivity check (was present in v0.11).
- Added optional Windows Update scan via a dedicated toolbar button. The main Run checks flow
  does not block on Windows Update, but the button lets you trigger it on demand.
- Fixed a scoping bug: $script:TrustedTpmPackageCache was being reset inside Close-ProgressWindow
  due to incorrect indentation, causing the CAI CAB to be re-downloaded on every EK cert window open.
- Removed the noisy 'Skipped rundll32 exports' INFO row from the repair flow.
- Minor: bumped version comment, updated help text.

.NOTES
Place these optional files next to the script or in a Tools folder if you want local fallback support:
TpmCoreProvisioning.dll
TpmTool.exe
TpmTasks.dll
tpmvsc.dll

The tool prefers the inbox Windows binaries first.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:Results = New-Object System.Collections.Generic.List[object]
$script:LogLines = New-Object System.Collections.Generic.List[string]
$script:FailCount = 0
$script:WarnCount = 0
$script:PassCount = 0
$script:InfoCount = 0
$script:LogBox = $null
$script:Grid = $null
$script:SummaryLabel = $null
$script:RunButton = $null
$script:RepairButton = $null
$script:CertButton = $null
$script:AikButton = $null
$script:ExportButton = $null
$script:ExportTpmLogsButton = $null
$script:ClearButton = $null
$script:WinUpdateButton = $null
$script:LastExportFolder = $null
$script:ProgressPanel      = $null   # inline strip at top (kept for label/bar)
$script:ProgressBar        = $null
$script:ProgressLabel      = $null
$script:ProgressDetailLabel= $null
$script:ProgressCurrent    = 0
$script:ProgressMax        = 1
$script:TrustedTpmPackageCache = $null

# Spinner overlay state
$script:SpinnerOverlay     = $null   # transparent Panel covering the main form
$script:SpinnerTimer       = $null   # WinForms Timer that redraws the arc
$script:SpinnerAngle       = 0       # current start angle of the arc
$script:SpinnerMessageLabel= $null   # big label inside the overlay
$script:SpinnerDetailLabel = $null   # smaller detail label


function Start-SpinnerOverlay {
    param(
        [string]$Message = 'Working...',
        [string]$Detail  = ''
    )

    if (-not $script:SpinnerOverlay) { return }

    $script:SpinnerMessageLabel.Text = $Message
    $script:SpinnerDetailLabel.Text  = $Detail
    $script:SpinnerAngle = 0
    $script:SpinnerOverlay.Visible = $true
    $script:SpinnerOverlay.BringToFront()

    if ($script:SpinnerTimer -and -not $script:SpinnerTimer.Enabled) {
        $script:SpinnerTimer.Start()
    }

    [System.Windows.Forms.Application]::DoEvents()
}

function Update-SpinnerOverlay {
    param(
        [string]$Message,
        [string]$Detail
    )

    if (-not $script:SpinnerOverlay -or -not $script:SpinnerOverlay.Visible) { return }

    if ($Message) { $script:SpinnerMessageLabel.Text = $Message }
    if ($PSBoundParameters.ContainsKey('Detail')) { $script:SpinnerDetailLabel.Text = $Detail }

    [System.Windows.Forms.Application]::DoEvents()
}

function Stop-SpinnerOverlay {
    if ($script:SpinnerTimer -and $script:SpinnerTimer.Enabled) {
        $script:SpinnerTimer.Stop()
    }

    if ($script:SpinnerOverlay) {
        $script:SpinnerOverlay.Visible = $false
    }

    [System.Windows.Forms.Application]::DoEvents()
}

function New-SpinnerOverlay {
    param([Parameter(Mandatory=$true)][System.Windows.Forms.Form]$ParentForm)

    # Semi-transparent overlay covering the whole client area
    $overlay = New-Object System.Windows.Forms.Panel
    $overlay.Dock = 'Fill'
    $overlay.Visible = $false
    $overlay.Cursor = [System.Windows.Forms.Cursors]::WaitCursor

    # Enable double buffering via reflection to prevent flicker during redraws
    $flags = [System.Reflection.BindingFlags]'Instance,NonPublic'
    $prop  = [System.Windows.Forms.Control].GetProperty('DoubleBuffered', $flags)
    if ($prop) { $prop.SetValue($overlay, $true, $null) }

    # Draw the frosted background + spinning arc on Paint
    $overlay.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

        # Semi-transparent white wash
        $wash = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(200, 255, 255, 255))
        $g.FillRectangle($wash, $sender.ClientRectangle)
        $wash.Dispose()

        # Card behind the spinner
        $cx = [int]($sender.ClientSize.Width  / 2)
        $cy = [int]($sender.ClientSize.Height / 2)
        $cardW = 280; $cardH = 180
        $cardX = $cx - [int]($cardW / 2)
        $cardY = $cy - [int]($cardH / 2)
        $cardRect = New-Object System.Drawing.Rectangle($cardX, $cardY, $cardW, $cardH)

        # Shadow
        $shadow = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 0, 0, 0))
        $g.FillRectangle($shadow, ($cardX + 4), ($cardY + 4), $cardW, $cardH)
        $shadow.Dispose()

        # Card fill
        $cardBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $g.FillRectangle($cardBrush, $cardRect)
        $cardBrush.Dispose()

        # Card border
        $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 220, 230), 1)
        $g.DrawRectangle($borderPen, $cardRect)
        $borderPen.Dispose()

        # Spinner ring: track (grey)
        $ringSize = 54
        $ringX = $cx - [int]($ringSize / 2)
        $ringY = $cardY + 22
        $trackPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(220, 220, 228), 6)
        $trackPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $trackPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawEllipse($trackPen, $ringX, $ringY, $ringSize, $ringSize)
        $trackPen.Dispose()

        # Spinner arc (blue, rotating)
        $arcPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 120, 212), 6)
        $arcPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $arcPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
        $g.DrawArc($arcPen, $ringX, $ringY, $ringSize, $ringSize, $script:SpinnerAngle, 100)
        $arcPen.Dispose()
    })

    # Message label (bold, under the ring)
    $msgLabel = New-Object System.Windows.Forms.Label
    $msgLabel.AutoSize = $false
    $msgLabel.TextAlign = 'MiddleCenter'
    $msgLabel.BackColor = [System.Drawing.Color]::Transparent
    $msgLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $msgLabel.ForeColor = [System.Drawing.Color]::FromArgb(26, 26, 46)
    $msgLabel.Text = ''
    $overlay.Controls.Add($msgLabel)

    # Detail label (smaller grey, below message)
    $detLabel = New-Object System.Windows.Forms.Label
    $detLabel.AutoSize = $false
    $detLabel.TextAlign = 'MiddleCenter'
    $detLabel.BackColor = [System.Drawing.Color]::Transparent
    $detLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $detLabel.ForeColor = [System.Drawing.Color]::DimGray
    $detLabel.Text = ''
    $overlay.Controls.Add($detLabel)

    # Reposition labels when overlay resizes
    $overlay.Add_Resize({
        param($sender, $e)
        $cx2 = [int]($sender.ClientSize.Width  / 2)
        $cy2 = [int]($sender.ClientSize.Height / 2)
        $cardW2 = 280; $cardH2 = 180
        $cardX2 = $cx2 - [int]($cardW2 / 2)
        $cardY2 = $cy2 - [int]($cardH2 / 2)

        $script:SpinnerMessageLabel.Location = New-Object System.Drawing.Point(($cardX2 + 10), ($cardY2 + 88))
        $script:SpinnerMessageLabel.Size     = New-Object System.Drawing.Size(260, 42)
        $script:SpinnerDetailLabel.Location  = New-Object System.Drawing.Point(($cardX2 + 10), ($cardY2 + 134))
        $script:SpinnerDetailLabel.Size      = New-Object System.Drawing.Size(260, 36)
    })

    # Timer - advances the angle and redraws
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 40   # ~25 fps - smooth without hammering the CPU

    $timer.Add_Tick({
        $script:SpinnerAngle = ($script:SpinnerAngle + 10) % 360
        if ($script:SpinnerOverlay -and $script:SpinnerOverlay.Visible) {
            # Only invalidate the card area, not the entire overlay
            $cx3 = [int]($script:SpinnerOverlay.ClientSize.Width  / 2)
            $cy3 = [int]($script:SpinnerOverlay.ClientSize.Height / 2)
            $cardRect3 = New-Object System.Drawing.Rectangle(($cx3 - 145), ($cy3 - 95), 290, 190)
            $script:SpinnerOverlay.Invalidate($cardRect3)
            $script:SpinnerOverlay.Update()
        }
    })

    $script:SpinnerOverlay      = $overlay
    $script:SpinnerTimer        = $timer
    $script:SpinnerMessageLabel = $msgLabel
    $script:SpinnerDetailLabel  = $detLabel

    $ParentForm.Controls.Add($overlay)
    $overlay.BringToFront()

    return $overlay
}


function Start-ProgressWindow {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][int]$Maximum,
        [string]$Message = 'Starting...'
    )

    $script:ProgressMax     = [Math]::Max($Maximum, 1)
    $script:ProgressCurrent = 0

    if ($script:ProgressBar) {
        $script:ProgressBar.Maximum = $script:ProgressMax
        $script:ProgressBar.Value   = 0
        $script:ProgressBar.Style   = [System.Windows.Forms.ProgressBarStyle]::Continuous
    }

    if ($script:ProgressLabel) {
        $script:ProgressLabel.Text = "$Title  -  $Message"
    }

    if ($script:ProgressDetailLabel) {
        $script:ProgressDetailLabel.Text = ''
    }

    if ($script:ProgressPanel) {
        $script:ProgressPanel.Visible = $true
    }

    Start-SpinnerOverlay -Message $Message -Detail ''
}

function Show-ProgressWindow {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [int]$Maximum = 3,
        [string]$Message = 'Starting...'
    )

    Start-ProgressWindow -Title $Title -Maximum $Maximum -Message $Message
}

function Update-ProgressWindow {
    param(
        [string]$Message,
        [string]$Detail,
        [switch]$Step
    )

    if ($Step) {
        $script:ProgressCurrent++
        if ($script:ProgressCurrent -gt $script:ProgressMax) {
            $script:ProgressCurrent = $script:ProgressMax
        }
        if ($script:ProgressBar) {
            $script:ProgressBar.Value = $script:ProgressCurrent
        }
    }

    if ($Message) {
        if ($script:ProgressLabel) { $script:ProgressLabel.Text = $Message }
        Update-SpinnerOverlay -Message $Message
    }

    if ($PSBoundParameters.ContainsKey('Detail')) {
        if ($script:ProgressDetailLabel) { $script:ProgressDetailLabel.Text = $Detail }
        Update-SpinnerOverlay -Detail $Detail
    }

    if ($script:ProgressPanel) { $script:ProgressPanel.Refresh() }

    [System.Windows.Forms.Application]::DoEvents()
}

function Close-ProgressWindow {
    Stop-SpinnerOverlay

    if ($script:ProgressPanel)      { $script:ProgressPanel.Visible = $false }
    if ($script:ProgressBar)        { $script:ProgressBar.Value = 0 }
    if ($script:ProgressLabel)      { $script:ProgressLabel.Text = '' }
    if ($script:ProgressDetailLabel){ $script:ProgressDetailLabel.Text = '' }

    $script:ProgressCurrent = 0
    $script:ProgressMax     = 1
    [System.Windows.Forms.Application]::DoEvents()
}

function Start-SleepWithDoEvents {
    param([Parameter(Mandatory=$true)][int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-AppLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO','PASS','WARN','FAIL','DEBUG')][string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$timestamp [$Level] $Message"
    $script:LogLines.Add($line) | Out-Null

    if ($script:LogBox) {
        $color = switch ($Level) {
            'PASS'  { [System.Drawing.Color]::ForestGreen }
            'WARN'  { [System.Drawing.Color]::DarkOrange }
            'FAIL'  { [System.Drawing.Color]::Firebrick }
            'DEBUG' { [System.Drawing.Color]::DimGray }
            default { [System.Drawing.Color]::Black }
        }

        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.SelectionLength = 0
        $script:LogBox.SelectionColor = $color
        $script:LogBox.AppendText($line + [Environment]::NewLine)
        $script:LogBox.SelectionColor = $script:LogBox.ForeColor
        $script:LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Get-ShortResultText {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Details = ''
    )

    if ([string]::IsNullOrWhiteSpace($Details)) {
        return $Status
    }

    if ($Details -match 'IsReadyInformation returned\s+([^\.\s]+)') {
        return "IsReady=$($Matches[1])"
    }

    if ($Details -match 'IsKeyAttestationCapable returned\s+([^\.\s]+)') {
        return "KeyAttestation=$($Matches[1])"
    }

    if ($Details -match 'exit code\s+(-?\d+)') {
        return "ExitCode=$($Matches[1])"
    }

    if ($Details -match 'LastTaskResult\s+(-?\d+)') {
        return "LastTaskResult=$($Matches[1])"
    }

    if ($Details -match 'AIK ErrorCode\s*(is|:)\s*(-?\d+)') {
        return "AIK=$($Matches[2])"
    }

    if ($Details -match 'ManufacturerCertificates=(\d+);\s*AdditionalCertificates=(\d+)') {
        return "Mfg=$($Matches[1]); Add=$($Matches[2])"
    }

    if ($Details -match 'Thumbprint:\s*([A-Fa-f0-9]+)') {
        $thumb = $Matches[1]
        if ($thumb.Length -gt 12) {
            return "Thumbprint=$($thumb.Substring(0,12))..."
        }
        return "Thumbprint=$thumb"
    }

    if ($Status -eq 'PASS') { return 'OK' }
    if ($Status -eq 'FAIL') { return 'Failed' }
    if ($Status -eq 'WARN') { return 'Needs attention' }
    return 'Info'
}

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Check,
        [ValidateSet('PASS','FAIL','WARN','INFO')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Details,
        [string]$Result = '',
        [string]$Remediation = ''
    )

    switch ($Status) {
        'PASS' { $script:PassCount++ }
        'FAIL' { $script:FailCount++ }
        'WARN' { $script:WarnCount++ }
        'INFO' { $script:InfoCount++ }
    }

    if ([string]::IsNullOrWhiteSpace($Result)) {
        $Result = Get-ShortResultText -Status $Status -Details $Details
    }

    $resultItem = [PSCustomObject]@{
        Category    = $Category
        Check       = $Check
        Status      = $Status
        Result      = $Result
        Details     = $Details
        Remediation = $Remediation
    }

    $script:Results.Add($resultItem) | Out-Null

    if ($script:Grid) {
        $index = $script:Grid.Rows.Add($Category, $Check, $Status, $Result, $Details, $Remediation)
        $row = $script:Grid.Rows[$index]

        switch ($Status) {
            'PASS' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
                $row.Cells[2].Style.ForeColor = [System.Drawing.Color]::ForestGreen
            }
            'FAIL' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
                $row.Cells[2].Style.ForeColor = [System.Drawing.Color]::Firebrick
            }
            'WARN' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LemonChiffon
                $row.Cells[2].Style.ForeColor = [System.Drawing.Color]::DarkOrange
            }
            'INFO' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::WhiteSmoke
                $row.Cells[2].Style.ForeColor = [System.Drawing.Color]::DimGray
            }
        }
    }

    Write-AppLog -Message "$Category | $Check | $Status | $Result | $Details" -Level $Status
}

function Reset-Results {
    $script:Results.Clear()
    $script:FailCount = 0
    $script:WarnCount = 0
    $script:PassCount = 0
    $script:InfoCount = 0

    if ($script:Grid) {
        $script:Grid.Rows.Clear()
    }

    if ($script:LogBox) {
        $script:LogBox.Clear()
    }

    $script:LogLines.Clear()
    Set-Summary -Text 'Running checks...' -State 'RUNNING'
}

function Set-Summary {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [ValidateSet('READY','BLOCKED','WARNING','RUNNING','IDLE')][string]$State = 'IDLE'
    )

    if (-not $script:SummaryLabel) { return }

    $script:SummaryLabel.Text = $Text

    switch ($State) {
        'READY' {
            $script:SummaryLabel.BackColor = [System.Drawing.Color]::Honeydew
            $script:SummaryLabel.ForeColor = [System.Drawing.Color]::ForestGreen
        }
        'BLOCKED' {
            $script:SummaryLabel.BackColor = [System.Drawing.Color]::MistyRose
            $script:SummaryLabel.ForeColor = [System.Drawing.Color]::Firebrick
        }
        'WARNING' {
            $script:SummaryLabel.BackColor = [System.Drawing.Color]::LemonChiffon
            $script:SummaryLabel.ForeColor = [System.Drawing.Color]::DarkOrange
        }
        'RUNNING' {
            $script:SummaryLabel.BackColor = [System.Drawing.Color]::AliceBlue
            $script:SummaryLabel.ForeColor = [System.Drawing.Color]::SteelBlue
        }
        default {
            $script:SummaryLabel.BackColor = [System.Drawing.Color]::WhiteSmoke
            $script:SummaryLabel.ForeColor = [System.Drawing.Color]::Black
        }
    }

    [System.Windows.Forms.Application]::DoEvents()
}

function Update-FinalSummary {
    if ($script:FailCount -gt 0) {
        Set-Summary -Text "Not ready for TPM attestation. $($script:FailCount) failed, $($script:WarnCount) warning, $($script:PassCount) passed." -State 'BLOCKED'
    }
    elseif ($script:WarnCount -gt 0) {
        Set-Summary -Text "Almost there. No failed checks, but $($script:WarnCount) warning needs attention." -State 'WARNING'
    }
    else {
        Set-Summary -Text "Ready for TPM attestation. $($script:PassCount) checks passed." -State 'READY'
    }
}

function Resolve-LocalOrInboxFile {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [string]$InboxPath
    )

    if ($InboxPath -and (Test-Path $InboxPath)) {
        return $InboxPath
    }

    $candidatePaths = @(
        (Join-Path $PSScriptRoot $FileName),
        (Join-Path (Join-Path $PSScriptRoot 'Tools') $FileName)
    )

    foreach ($candidate in $candidatePaths) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-FileVersionSummary {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $item = Get-Item -Path $Path -ErrorAction Stop
        $version = $item.VersionInfo.FileVersion
        if ([string]::IsNullOrWhiteSpace($version)) { $version = 'No file version' }
        return "Path=$($item.FullName); Version=$version; Size=$($item.Length) bytes; Modified=$($item.LastWriteTime)"
    }
    catch {
        return $_.Exception.Message
    }
}

function Test-TpmHelperFiles {
    $helpers = @(
        [PSCustomObject]@{ FileName = 'TpmCoreProvisioning.dll'; InboxPath = (Join-Path $env:WINDIR 'System32\tpmcoreprovisioning.dll'); Required = $true;  Purpose = 'TPM EK, AIK, and provisioning helper exports' },
        [PSCustomObject]@{ FileName = 'TpmTool.exe';              InboxPath = (Join-Path $env:WINDIR 'System32\tpmtool.exe');              Required = $false; Purpose = 'TPM diagnostic output' },
        [PSCustomObject]@{ FileName = 'TpmTasks.dll';             InboxPath = (Join-Path $env:WINDIR 'System32\TpmTasks.dll');             Required = $false; Purpose = 'Secure Boot update task helper, not used for EK or AIK attestation' },
        [PSCustomObject]@{ FileName = 'tpmvsc.dll';               InboxPath = (Join-Path $env:WINDIR 'System32\tpmvsc.dll');               Required = $false; Purpose = 'TPM virtual smart card helper, not used for Autopilot EK or AIK attestation' }
    )

    foreach ($helper in $helpers) {
        $path = Resolve-LocalOrInboxFile -FileName $helper.FileName -InboxPath $helper.InboxPath
        if ($path) {
            $status = if ($helper.Required) { 'PASS' } else { 'INFO' }
            Add-Result -Category 'Startup' -Check $helper.FileName -Status $status -Result $helper.Purpose -Details (Get-FileVersionSummary -Path $path)
        }
        elseif ($helper.Required) {
            Add-Result -Category 'Startup' -Check $helper.FileName -Status 'WARN' -Result 'Missing' -Details "$($helper.FileName) was not found." -Remediation 'Use the inbox file or place it next to the script or in .\Tools.'
        }
        else {
            Add-Result -Category 'Startup' -Check $helper.FileName -Status 'INFO' -Result 'Not found' -Details "$($helper.FileName) was not found. This is not required for the main TPM attestation checks."
        }
    }
}

function Convert-NativeExitCodeText {
    param([int]$ExitCode)

    switch ($ExitCode) {
        0 { return 'Success' }
        -999 { return 'Timed out' }
        -1073741819 { return 'Access violation. This export is not reliable when called through rundll32 on this build.' }
        default {
            if ($ExitCode -lt 0) {
                $hexCode = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$ExitCode), 0)
                return ("Native failure 0x{0:X8}" -f $hexCode)
            }
            return "ExitCode=$ExitCode"
        }
    }
}

function Invoke-ProcessHidden {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string]$Arguments = '',
        [int]$TimeoutSeconds = 60
    )

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        [void]$process.Start()

        # Pump the UI message queue while waiting so the spinner timer can tick.
        # WaitForExit(ms) returns true if exited within the interval, false if still running.
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $exited   = $false
        while (-not $exited) {
            $exited = $process.WaitForExit(50)   # wait 50ms then yield
            [System.Windows.Forms.Application]::DoEvents()
            if (-not $exited -and (Get-Date) -gt $deadline) {
                try { $process.Kill() } catch { }
                return [PSCustomObject]@{
                    ExitCode = -999
                    Output   = ''
                    Error    = "Timed out after $TimeoutSeconds seconds"
                }
            }
        }

        return [PSCustomObject]@{
            ExitCode = $process.ExitCode
            Output   = $process.StandardOutput.ReadToEnd()
            Error    = $process.StandardError.ReadToEnd()
        }
    }
    catch {
        return [PSCustomObject]@{
            ExitCode = -1
            Output   = ''
            Error    = $_.Exception.Message
        }
    }
}

function Invoke-TpmCoreProvisioningFunction {
    param(
        [Parameter(Mandatory = $true)][string]$FunctionName,
        [int]$TimeoutSeconds = 60
    )

    $rundll32 = Join-Path $env:WINDIR 'System32\rundll32.exe'
    $dllPath = Resolve-LocalOrInboxFile -FileName 'TpmCoreProvisioning.dll' -InboxPath (Join-Path $env:WINDIR 'System32\tpmcoreprovisioning.dll')

    if (-not $dllPath) {
        Add-Result -Category 'Attestation Action' -Check $FunctionName -Status 'FAIL' -Result 'DLL missing' -Details 'TpmCoreProvisioning.dll was not found.' -Remediation 'Use the inbox DLL or place it next to the script.'
        return
    }

    Write-AppLog -Message "Running $FunctionName through $dllPath" -Level 'DEBUG'
    $result = Invoke-ProcessHidden -FilePath $rundll32 -Arguments "`"$dllPath`",$FunctionName" -TimeoutSeconds $TimeoutSeconds
    $exitText = Convert-NativeExitCodeText -ExitCode $result.ExitCode
    $combinedOutput = (($result.Output, $result.Error) -join ' ').Trim()

    if ($result.ExitCode -eq 0) {
        Add-Result -Category 'Attestation Action' -Check $FunctionName -Status 'PASS' -Result $exitText -Details 'Function was started successfully.'
    }
    elseif ($result.ExitCode -eq -999) {
        Add-Result -Category 'Attestation Action' -Check $FunctionName -Status 'WARN' -Result $exitText -Details "Function timed out after $TimeoutSeconds seconds. $combinedOutput" -Remediation 'This function may wait for network or provisioning work. Check TPM event logs and post action result rows.'
    }
    elseif ($result.ExitCode -eq -1073741819) {
        Add-Result -Category 'Attestation Action' -Check $FunctionName -Status 'WARN' -Result $exitText -Details "Function returned 0xC0000005 when called through rundll32. $combinedOutput" -Remediation 'Do not treat this as a TPM failure by itself. Validate the post action result rows instead.'
    }
    else {
        Add-Result -Category 'Attestation Action' -Check $FunctionName -Status 'WARN' -Result $exitText -Details "Function returned exit code $($result.ExitCode). $combinedOutput" -Remediation 'Check TPM event logs and rerun the readiness checks.'
    }
}

function Test-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [int]$Port = 443,
        [int]$TimeoutMilliseconds = 4000
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        $success = $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)

        if (-not $success) {
            $client.Close()
            return $false
        }

        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}

function Test-IntunePortalContent {
    # Re-introduced from the v0.11 test-managemicrosoft check.
    # Tests whether the Intune portal HTML contains the expected Microsoft copyright string.
    # When this is missing it usually indicates a proxy or TLS inspection issue that causes
    # OOBEAADV10 / 502 errors during Autopilot pre-provisioning.
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'AutopilotTpmAttestationTool/0.23')
        $html = $wc.DownloadString('https://portal.manage.microsoft.com')

        if ($html -like '*Copyright (C) Microsoft Corporation*' -or $html -like '*microsoft.com*') {
            Add-Result -Category 'Connectivity' -Check 'Intune portal content (OOBEAADV10)' -Status 'PASS' -Details 'portal.manage.microsoft.com returned expected Microsoft content. No OOBEAADV10 indicators detected.'
        }
        else {
            Add-Result -Category 'Connectivity' -Check 'Intune portal content (OOBEAADV10)' -Status 'WARN' -Details 'portal.manage.microsoft.com did not return expected Microsoft content. This can indicate a proxy or TLS inspection issue that causes OOBEAADV10 errors.' -Remediation 'Check proxy bypass rules, TLS inspection exclusions, and review https://call4cloud.nl/2022/07/oobeaadv10-return-of-the-502-error/ for guidance.'
        }
    }
    catch {
        Add-Result -Category 'Connectivity' -Check 'Intune portal content (OOBEAADV10)' -Status 'WARN' -Details "Could not fetch portal.manage.microsoft.com: $($_.Exception.Message)" -Remediation 'Verify network access and proxy configuration. OOBEAADV10 errors during Autopilot pre-provisioning are often caused by proxy issues on this endpoint.'
    }
}

function Test-ConnectivityChecks {
    Write-AppLog -Message 'Checking TPM and Autopilot related endpoints' -Level 'INFO'

    $endpoints = @(
        [PSCustomObject]@{ Name = 'Intune portal'; Host = 'portal.manage.microsoft.com'; Required = $true },
        [PSCustomObject]@{ Name = 'Autopilot ZTD service'; Host = 'ztd.dds.microsoft.com'; Required = $true },
        [PSCustomObject]@{ Name = 'Azure'; Host = 'azure.net'; Required = $true },
        [PSCustomObject]@{ Name = 'Intel EK service'; Host = 'ekop.intel.com'; Required = $false },
        [PSCustomObject]@{ Name = 'Qualcomm EK service'; Host = 'ekcert.spserv.microsoft.com'; Required = $false },
        [PSCustomObject]@{ Name = 'AMD fTPM service'; Host = 'ftpm.amd.com'; Required = $false }
    )

    foreach ($endpoint in $endpoints) {
        Update-ProgressWindow -Message "Connectivity - testing $($endpoint.Host)" -Detail "TCP port 443..."
        $ok = Test-TcpEndpoint -HostName $endpoint.Host
        if ($ok) {
            Add-Result -Category 'Connectivity' -Check $endpoint.Name -Status 'PASS' -Details "$($endpoint.Host):443 reachable"
        }
        elseif ($endpoint.Required) {
            Add-Result -Category 'Connectivity' -Check $endpoint.Name -Status 'FAIL' -Details "$($endpoint.Host):443 not reachable" -Remediation 'Check proxy, TLS inspection, firewall, DNS, or network restrictions.'
        }
        else {
            Add-Result -Category 'Connectivity' -Check $endpoint.Name -Status 'WARN' -Details "$($endpoint.Host):443 not reachable" -Remediation 'This may be fine when the TPM vendor does not use that endpoint, but check firewall rules if EK retrieval fails.'
        }
    }

    Test-IntunePortalContent
}

function Test-HardwareInfo {
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

        Add-Result -Category 'Hardware' -Check 'Manufacturer' -Status 'INFO' -Details "$($cs.Manufacturer) $($cs.Model)"
        Add-Result -Category 'Hardware' -Check 'Serial number' -Status 'INFO' -Details "$($bios.SerialNumber)"
    }
    catch {
        Add-Result -Category 'Hardware' -Check 'CIM hardware query' -Status 'FAIL' -Details $_.Exception.Message -Remediation 'Verify that WMI/CIM is healthy.'
    }
}

function Test-WindowsLicense {
    try {
        $lic = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $productKey = $lic.OA3xOriginalProductKey
        $productType = $lic.OA3xOriginalProductKeyDescription

        if ($productKey) {
            $maskedKey = '*****-*****-*****-*****-' + $productKey.Substring($productKey.Length - 5)
        }
        else {
            $maskedKey = 'Not found'
        }

        Add-Result -Category 'Windows' -Check 'BIOS product key' -Status 'INFO' -Details $maskedKey

        if ($productType -match 'Professional|Enterprise|Education|Pro') {
            Add-Result -Category 'Windows' -Check 'BIOS license edition' -Status 'PASS' -Details $productType
        }
        else {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($os.Caption -match 'Professional|Enterprise|Education|Pro') {
                Add-Result -Category 'Windows' -Check 'Installed Windows edition' -Status 'PASS' -Details $os.Caption
            }
            else {
                Add-Result -Category 'Windows' -Check 'Windows edition' -Status 'WARN' -Details "BIOS: $productType Installed: $($os.Caption)" -Remediation 'Verify that the device runs a supported Windows edition for your enrollment scenario.'
            }
        }
    }
    catch {
        Add-Result -Category 'Windows' -Check 'License query' -Status 'WARN' -Details $_.Exception.Message
    }
}

function Test-TimeService {
    try {
        $service = Get-Service -Name W32Time -ErrorAction Stop

        if ($service.Status -ne 'Running') {
            Add-Result -Category 'Windows' -Check 'Windows Time service' -Status 'WARN' -Details "Current status: $($service.Status)" -Remediation 'Start W32Time and resync before attestation.'
            return
        }

        $resync = Invoke-ProcessHidden -FilePath (Join-Path $env:WINDIR 'System32\w32tm.exe') -Arguments '/resync' -TimeoutSeconds 20
        if ($resync.ExitCode -eq 0) {
            Add-Result -Category 'Windows' -Check 'Time sync' -Status 'PASS' -Details 'W32Time is running and resync was requested.'
        }
        else {
            Add-Result -Category 'Windows' -Check 'Time sync' -Status 'WARN' -Details "W32Time is running, but resync returned $($resync.ExitCode)." -Remediation 'Check time source and domain or NTP configuration.'
        }
    }
    catch {
        Add-Result -Category 'Windows' -Check 'Windows Time service' -Status 'FAIL' -Details $_.Exception.Message
    }
}

function Get-TpmCimInstanceSafe {
    try {
        return Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName 'Win32_TPM' -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Test-TpmBaseState {
    $tpmCim = Get-TpmCimInstanceSafe

    if (-not $tpmCim) {
        Add-Result -Category 'TPM' -Check 'TPM WMI provider' -Status 'FAIL' -Details 'Win32_TPM could not be queried.' -Remediation 'Check BIOS TPM state, TPM drivers, and WMI health.'
        return
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop

        if ($tpm.TpmPresent) {
            Add-Result -Category 'TPM' -Check 'TPM present' -Status 'PASS' -Details 'TPM is present.'
        }
        else {
            Add-Result -Category 'TPM' -Check 'TPM present' -Status 'FAIL' -Details 'TPM is not present.' -Remediation 'Enable TPM in firmware.'
        }

        if ($tpm.TpmReady) {
            Add-Result -Category 'TPM' -Check 'TPM ready' -Status 'PASS' -Details 'TPM is ready.'
        }
        else {
            Add-Result -Category 'TPM' -Check 'TPM ready' -Status 'FAIL' -Details 'TPM is not ready.' -Remediation 'Provision TPM or check TPM event logs.'
        }

        if ($tpm.TpmOwned) {
            Add-Result -Category 'TPM' -Check 'TPM owned' -Status 'PASS' -Details 'TPM is owned.'
        }
        else {
            Add-Result -Category 'TPM' -Check 'TPM owned' -Status 'FAIL' -Details 'TPM is not owned.' -Remediation 'Complete TPM provisioning.'
        }
    }
    catch {
        Add-Result -Category 'TPM' -Check 'Get-Tpm' -Status 'WARN' -Details $_.Exception.Message
    }

    try {
        $specVersion = [string]$tpmCim.SpecVersion
        if ($specVersion -match '1\.2|1\.15') {
            Add-Result -Category 'TPM' -Check 'TPM version' -Status 'FAIL' -Details "SpecVersion: $specVersion" -Remediation 'TPM 2.0 is required for this attestation flow.'
        }
        elseif ($specVersion -match '2\.0') {
            Add-Result -Category 'TPM' -Check 'TPM version' -Status 'PASS' -Details "SpecVersion: $specVersion"
        }
        else {
            Add-Result -Category 'TPM' -Check 'TPM version' -Status 'WARN' -Details "SpecVersion: $specVersion" -Remediation 'Verify the TPM version manually.'
        }
    }
    catch {
        Add-Result -Category 'TPM' -Check 'TPM version' -Status 'WARN' -Details $_.Exception.Message
    }
}

function Test-TpmReadyForAttestation {
    $tpmCim = Get-TpmCimInstanceSafe

    if (-not $tpmCim) {
        Add-Result -Category 'Attestation' -Check 'Ready information' -Status 'FAIL' -Details 'TPM WMI provider unavailable.'
        return
    }

    try {
        $attestation = $tpmCim | Invoke-CimMethod -MethodName IsReadyInformation -ErrorAction Stop
        $code = [int64]$attestation.Information

        if ($code -eq 0) {
            Add-Result -Category 'Attestation' -Check 'Ready information' -Status 'PASS' -Details 'IsReadyInformation returned 0.'
        }
        else {
            $known = switch ($code) {
                262144   { 'EK certificate appears to be missing.' }
                16777216 { 'TPM health attestation vulnerability state was reported.' }
                default  { "IsReadyInformation returned $code." }
            }

            Add-Result -Category 'Attestation' -Check 'Ready information' -Status 'FAIL' -Details $known -Remediation 'Run TPM maintenance and check EK certificate availability.'
        }
    }
    catch {
        Add-Result -Category 'Attestation' -Check 'Ready information' -Status 'FAIL' -Details $_.Exception.Message
    }
}

function Test-WbclPresence {
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices'
    try {
        $wbcl = Get-ItemProperty -Path $path -Name 'WBCL' -ErrorAction Stop
        if ($null -ne $wbcl.WBCL) {
            Add-Result -Category 'Attestation' -Check 'Measured boot log' -Status 'PASS' -Details 'WBCL registry value exists.'
        }
        else {
            Add-Result -Category 'Attestation' -Check 'Measured boot log' -Status 'FAIL' -Details 'WBCL registry value is empty.' -Remediation 'Reboot the device and check measured boot state.'
        }
    }
    catch {
        Add-Result -Category 'Attestation' -Check 'Measured boot log' -Status 'FAIL' -Details 'WBCL registry value does not exist.' -Remediation 'Reboot the device and check Secure Boot and measured boot state.'
    }
}


function Test-TpmMaintenanceReadiness {
    try {
        $oobePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE'
        $eula = Get-ItemProperty -Path $oobePath -Name 'SetupDisplayedEula' -ErrorAction SilentlyContinue

        if ($null -ne $eula -and [int]$eula.SetupDisplayedEula -eq 1) {
            Add-Result -Category 'TPM Maintenance' -Check 'SetupDisplayedEula' -Status 'PASS' -Result 'Present' -Details 'SetupDisplayedEula is set to 1. TPM-Maintenance is allowed to run.'
        }
        else {
            Add-Result -Category 'TPM Maintenance' -Check 'SetupDisplayedEula' -Status 'FAIL' -Result 'Missing or not accepted' -Details 'SetupDisplayedEula is missing or not set to 1. TPM-Maintenance can refuse to do its work on affected devices.' -Remediation 'Set SetupDisplayedEula to 1 or use Kickstart TPM attestation before starting pre provisioning.'
        }
    }
    catch {
        Add-Result -Category 'TPM Maintenance' -Check 'SetupDisplayedEula' -Status 'WARN' -Result 'Could not read' -Details $_.Exception.Message
    }

    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -ErrorAction Stop
        $taskInfo = Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -ErrorAction SilentlyContinue

        if ($task -and $taskInfo) {
            Add-Result -Category 'TPM Maintenance' -Check 'TPM-Maintenance task' -Status 'PASS' -Result 'Present' -Details "Task exists. State=$($task.State). LastTaskResult=$($taskInfo.LastTaskResult). LastRunTime=$($taskInfo.LastRunTime)."
        }
        else {
            Add-Result -Category 'TPM Maintenance' -Check 'TPM-Maintenance task' -Status 'WARN' -Result 'Present, no info' -Details 'The task exists, but no task info was returned.'
        }
    }
    catch {
        Add-Result -Category 'TPM Maintenance' -Check 'TPM-Maintenance task' -Status 'FAIL' -Result 'Missing or inaccessible' -Details $_.Exception.Message -Remediation 'Check the Microsoft\Windows\TPM scheduled task folder.'
    }

    try {
        $taskStatePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\taskStates'
        $ekState = Get-ItemProperty -Path $taskStatePath -Name 'EkCertificatePresent' -ErrorAction SilentlyContinue

        if ($null -ne $ekState) {
            Add-Result -Category 'TPM Maintenance' -Check 'EkCertificatePresent task state' -Status 'PASS' -Result 'Present' -Details "TaskStates EkCertificatePresent exists. Value=$($ekState.EkCertificatePresent)."
        }
        else {
            Add-Result -Category 'TPM Maintenance' -Check 'EkCertificatePresent task state' -Status 'FAIL' -Result 'Missing' -Details 'The TaskStates EkCertificatePresent value is missing. This usually means TPM-Maintenance did not complete the EK state write.' -Remediation 'Run Kickstart TPM attestation or run TPM-Maintenance after making sure SetupDisplayedEula is 1.'
        }
    }
    catch {
        Add-Result -Category 'TPM Maintenance' -Check 'EkCertificatePresent task state' -Status 'WARN' -Result 'Could not read' -Details $_.Exception.Message
    }
}

function Test-EkCertificateStore {
    $storePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates'

    if (Test-Path $storePath) {
        $certs = @(Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue)
        if ($certs.Count -gt 0) {
            Add-Result -Category 'EK Certificate' -Check 'Registry EK certificate store' -Status 'PASS' -Details "$($certs.Count) certificate item found."
        }
        else {
            Add-Result -Category 'EK Certificate' -Check 'Registry EK certificate store' -Status 'FAIL' -Details 'EKCertStore exists, but no certificates were found.' -Remediation 'Run TPM maintenance or retrieve EK certificate from vendor service.'
        }
    }
    else {
        Add-Result -Category 'EK Certificate' -Check 'Registry EK certificate store' -Status 'FAIL' -Details 'EKCertStore path does not exist.' -Remediation 'Run TPM maintenance or retrieve EK certificate from vendor service.'
    }

    try {
        $ek = Get-TpmEndorsementKeyInfo -ErrorAction Stop
        if ($ek.IsPresent) {
            Add-Result -Category 'EK Certificate' -Check 'Endorsement key' -Status 'PASS' -Details 'Endorsement key is present.'
        }
        else {
            Add-Result -Category 'EK Certificate' -Check 'Endorsement key' -Status 'FAIL' -Details 'Endorsement key is not present.' -Remediation 'Check TPM state and EK provisioning.'
        }

        $manufacturerCerts = @($ek.ManufacturerCertificates)
        $additionalCerts = @($ek.AdditionalCertificates)

        if (($manufacturerCerts.Count -gt 0) -or ($additionalCerts.Count -gt 0)) {
            Add-Result -Category 'EK Certificate' -Check 'EK certificate chain' -Status 'PASS' -Details "Manufacturer certificates: $($manufacturerCerts.Count). Additional certificates: $($additionalCerts.Count)."
        }
        else {
            Add-Result -Category 'EK Certificate' -Check 'EK certificate chain' -Status 'FAIL' -Details 'No manufacturer or additional EK certificates found.' -Remediation 'Run TPM maintenance and verify vendor EK retrieval endpoint access.'
        }
    }
    catch {
        Add-Result -Category 'EK Certificate' -Check 'Get-TpmEndorsementKeyInfo' -Status 'WARN' -Details $_.Exception.Message
    }
}



function Get-CertificateExtensionText {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$Oid
    )

    try {
        foreach ($extension in $Certificate.Extensions) {
            if ($extension.Oid.Value -eq $Oid) {
                return (($extension.Format($true) -replace "`r|`n", ' ') -replace '\s+', ' ').Trim()
            }
        }
    }
    catch { }

    return ''
}

function Get-CertificateKeySizeText {
    param(
        [Parameter(Mandatory = $true)]$Certificate
    )

    try {
        if ($Certificate.PublicKey -and $Certificate.PublicKey.Key) {
            return [string]$Certificate.PublicKey.Key.KeySize
        }
    }
    catch { }

    try {
        $rsa = $Certificate.GetRSAPublicKey()
        if ($rsa) {
            return [string]$rsa.KeySize
        }
    }
    catch { }

    try {
        $ecdsa = $Certificate.GetECDsaPublicKey()
        if ($ecdsa) {
            return [string]$ecdsa.KeySize
        }
    }
    catch { }

    return ''
}

function Get-CertificateChainStatusText {
    param(
        [Parameter(Mandatory = $true)]$ChainElement
    )

    try {
        if ($ChainElement.ChainElementStatus.Count -eq 0) {
            return 'OK'
        }

        $items = New-Object System.Collections.Generic.List[string]
        foreach ($status in $ChainElement.ChainElementStatus) {
            $statusText = ([string]$status.StatusInformation).Trim()
            if ([string]::IsNullOrWhiteSpace($statusText)) {
                $statusText = [string]$status.Status
            }
            else {
                $statusText = "$($status.Status): $statusText"
            }
            $items.Add($statusText) | Out-Null
        }

        return ($items -join '; ')
    }
    catch {
        return ''
    }
}

function Convert-CertificateForDisplay {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$Type
    )

    $thumbprint = ''
    $subject = ''
    $issuer = ''
    $serialNumber = ''
    $notBefore = ''
    $notAfter = ''
    $signatureAlgorithm = ''
    $publicKeyAlgorithm = ''
    $keySize = ''
    $version = ''
    $basicConstraints = ''
    $keyUsage = ''
    $enhancedKeyUsage = ''
    $subjectKeyIdentifier = ''
    $authorityKeyIdentifier = ''
    $authorityInfoAccess = ''
    $isSelfSigned = ''

    try { $thumbprint = [string]$Certificate.Thumbprint } catch { }
    try { $subject = [string]$Certificate.Subject } catch { }
    try { $issuer = [string]$Certificate.Issuer } catch { }
    try { $serialNumber = [string]$Certificate.SerialNumber } catch { }
    try { $notBefore = [string]$Certificate.NotBefore } catch { }
    try { $notAfter = [string]$Certificate.NotAfter } catch { }
    try { $signatureAlgorithm = [string]$Certificate.SignatureAlgorithm.FriendlyName } catch { }
    try { $publicKeyAlgorithm = [string]$Certificate.PublicKey.Oid.FriendlyName } catch { }
    try { $keySize = Get-CertificateKeySizeText -Certificate $Certificate } catch { }
    try { $version = [string]$Certificate.Version } catch { }
    try { $basicConstraints = Get-CertificateExtensionText -Certificate $Certificate -Oid '2.5.29.19' } catch { }
    try { $keyUsage = Get-CertificateExtensionText -Certificate $Certificate -Oid '2.5.29.15' } catch { }
    try { $enhancedKeyUsage = Get-CertificateExtensionText -Certificate $Certificate -Oid '2.5.29.37' } catch { }
    try { $subjectKeyIdentifier = Get-CertificateExtensionText -Certificate $Certificate -Oid '2.5.29.14' } catch { }
    try { $authorityKeyIdentifier = Get-CertificateExtensionText -Certificate $Certificate -Oid '2.5.29.35' } catch { }
    try { $authorityInfoAccess = Get-CertificateExtensionText -Certificate $Certificate -Oid '1.3.6.1.5.5.7.1.1' } catch { }
    try { $isSelfSigned = [string]($Certificate.Subject -eq $Certificate.Issuer) } catch { }

    [PSCustomObject]@{
        Type                   = $Type
        Thumbprint             = $thumbprint
        Subject                = $subject
        Issuer                 = $issuer
        SerialNumber           = $serialNumber
        NotBefore              = $notBefore
        NotAfter               = $notAfter
        SignatureAlgorithm     = $signatureAlgorithm
        PublicKeyAlgorithm     = $publicKeyAlgorithm
        KeySize                = $keySize
        Version                = $version
        BasicConstraints       = $basicConstraints
        KeyUsage               = $keyUsage
        EnhancedKeyUsage       = $enhancedKeyUsage
        SubjectKeyIdentifier   = $subjectKeyIdentifier
        AuthorityKeyIdentifier = $authorityKeyIdentifier
        AuthorityInfoAccess    = $authorityInfoAccess
        IsSelfSigned           = $isSelfSigned
    }
}

function Get-TpmEndorsementCertificateObjects {
    param(
        [switch]$AddToResults
    )

    $certList = New-Object System.Collections.Generic.List[object]

    try {
        $ek = Get-TpmEndorsementKeyInfo -ErrorAction Stop

        if ($AddToResults) {
            if ($ek.IsPresent) {
                Add-Result -Category 'EK Certificate' -Check 'Endorsement key' -Status 'PASS' -Details 'Endorsement key is present.'
            }
            else {
                Add-Result -Category 'EK Certificate' -Check 'Endorsement key' -Status 'FAIL' -Details 'Endorsement key is not present.' -Remediation 'Check TPM state and EK provisioning.'
            }
        }

        $manufacturerCerts = @()
        $additionalCerts = @()

        if (($ek.PSObject.Properties.Name -contains 'ManufacturerCertificates') -and $null -ne $ek.ManufacturerCertificates) {
            $manufacturerCerts = @($ek.ManufacturerCertificates)
        }

        if (($ek.PSObject.Properties.Name -contains 'AdditionalCertificates') -and $null -ne $ek.AdditionalCertificates) {
            $additionalCerts = @($ek.AdditionalCertificates)
        }

        foreach ($cert in $manufacturerCerts) {
            if ($null -eq $cert) { continue }
            $certList.Add([PSCustomObject]@{
                Type        = 'Manufacturer'
                Certificate = $cert
            }) | Out-Null
        }

        foreach ($cert in $additionalCerts) {
            if ($null -eq $cert) { continue }
            $certList.Add([PSCustomObject]@{
                Type        = 'Additional'
                Certificate = $cert
            }) | Out-Null
        }

        if ($AddToResults) {
            if ($certList.Count -gt 0) {
                foreach ($item in $certList) {
                    $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type
                    Add-Result -Category 'EK Certificate' -Check "$($item.Type) certificate" -Status 'PASS' -Details "Thumbprint: $($display.Thumbprint). Subject: $($display.Subject). Issuer: $($display.Issuer). Valid until: $($display.NotAfter)."
                }

                Add-Result -Category 'EK Certificate' -Check 'EK certificate details' -Status 'PASS' -Details "$($certList.Count) endorsement certificate(s) returned by Get-TpmEndorsementKeyInfo."
            }
            else {
                Add-Result -Category 'EK Certificate' -Check 'EK certificate details' -Status 'FAIL' -Details 'No ManufacturerCertificates or AdditionalCertificates were returned by Get-TpmEndorsementKeyInfo.' -Remediation 'Run TPM attestation actions and verify vendor EK retrieval endpoint access.'
            }
        }
    }
    catch {
        if ($AddToResults) {
            Add-Result -Category 'EK Certificate' -Check 'Get-TpmEndorsementKeyInfo' -Status 'WARN' -Details $_.Exception.Message
        }
    }

    return $certList.ToArray()
}

function Get-TpmEndorsementCertificatesForDisplay {
    param(
        [switch]$AddToResults
    )

    $objects = @(Get-TpmEndorsementCertificateObjects -AddToResults:$AddToResults)
    $displayList = New-Object System.Collections.Generic.List[object]

    foreach ($item in $objects) {
        try {
            $displayList.Add((Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type)) | Out-Null
        }
        catch { }
    }

    return $displayList.ToArray()
}

function Import-CertificatesFromFile {
    param(
        [Parameter(Mandatory = $true)]$File
    )

    $items = New-Object System.Collections.Generic.List[object]

    try {
        $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $collection.Import($File.FullName)

        foreach ($cert in $collection) {
            if ($null -eq $cert) { continue }
            $items.Add([PSCustomObject]@{
                FileName    = $File.Name
                Certificate = $cert
            }) | Out-Null
        }
    }
    catch {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($File.FullName)
            $items.Add([PSCustomObject]@{
                FileName    = $File.Name
                Certificate = $cert
            }) | Out-Null
        }
        catch { }
    }

    return $items.ToArray()
}


function Convert-ToCaiComparableText {
    param(
        [AllowNull()][string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    return (($Text.ToLowerInvariant()) -replace '[^a-z0-9]', '')
}

function Get-CaiUsefulTokens {
    param(
        [AllowNull()][string]$Text
    )

    $tokens = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $tokens.ToArray() }

    $ignore = @{
        'cn' = $true; 'o' = $true; 'ou' = $true; 'c' = $true; 'l' = $true; 's' = $true
        'ca' = $true; 'ek' = $true; 'tpm' = $true; 'aik' = $true; 'cert' = $true
        'certificate' = $true; 'certificates' = $true; 'intermediate' = $true; 'root' = $true
        'keyid' = $true; 'key' = $true; 'id' = $true; 'family' = $true
    }

    foreach ($token in ($Text.ToLowerInvariant() -split '[^a-z0-9]+')) {
        if ([string]::IsNullOrWhiteSpace($token)) { continue }
        if ($token.Length -lt 2) { continue }
        if ($ignore.ContainsKey($token)) { continue }
        if (-not $tokens.Contains($token)) { $tokens.Add($token) | Out-Null }
    }

    return $tokens.ToArray()
}

function Get-CertificateCommonName {
    param(
        [AllowNull()][string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) { return '' }
    if ($Subject -match '(?:^|,\s*)CN\s*=\s*([^,]+)') {
        return ([string]$matches[1]).Trim()
    }

    return ''
}

function Get-MicrosoftTpmCaiVersionEntries {
    param(
        [AllowNull()][string]$VersionText
    )

    $entries = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($VersionText)) { return $entries.ToArray() }

    $currentAction = ''
    $currentGroup = ''
    $currentDate = ''
    $lines = $VersionText -split "`r`n|`n|`r"

    foreach ($line in $lines) {
        $trimmed = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

        if ($trimmed -match '^\d{1,2}[-/][A-Za-z]+[-/]\d{4}$' -or $trimmed -match '^\d{4}[-/]\d{1,2}[-/]\d{1,2}$') {
            $currentDate = $trimmed
            $currentAction = ''
            $currentGroup = ''
            continue
        }

        if ($trimmed -match '^(Added|Removed)\s+the\s+following\s+(.+?)\s+Certificates\s*$') {
            $currentAction = $matches[1]
            $currentGroup = $matches[2]
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($currentAction) -and $trimmed -match '\.(cer|crt|pem|p7b|p7c)$') {
            $entries.Add([PSCustomObject]@{
                Action     = $currentAction
                Group      = $currentGroup
                Date       = $currentDate
                FileName   = $trimmed
                Normalized = Convert-ToCaiComparableText -Text $trimmed
            }) | Out-Null
        }
    }

    return $entries.ToArray()
}

function Add-CaiLookupValue {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Table,
        [AllowNull()][string]$Key,
        [AllowNull()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    if ([string]::IsNullOrWhiteSpace($Value)) { $Value = '<unknown>' }

    if (-not $Table.ContainsKey($Key)) {
        $Table[$Key] = New-Object System.Collections.Generic.List[string]
    }

    if (-not $Table[$Key].Contains($Value)) {
        $Table[$Key].Add($Value) | Out-Null
    }
}

function Add-UniqueString {
    param(
        [Parameter(Mandatory = $true)]$List,
        [AllowNull()][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if (-not $List.Contains($Value)) { $List.Add($Value) | Out-Null }
}

function Get-CaiVersionHistoryMatches {
    param(
        [Parameter(Mandatory = $true)]$VersionEntries,
        [Parameter(Mandatory = $true)]$Display,
        [Parameter(Mandatory = $true)]$ChainRows,
        [Parameter(Mandatory = $true)]$ActiveSourceFiles
    )

    $matchesList = New-Object System.Collections.Generic.List[object]
    $activeFileLookup = @{}
    foreach ($sourceFile in @($ActiveSourceFiles)) {
        if ([string]::IsNullOrWhiteSpace($sourceFile)) { continue }
        $activeFileLookup[$sourceFile.ToLowerInvariant()] = $true
    }

    $hintTexts = New-Object System.Collections.Generic.List[string]
    Add-UniqueString -List $hintTexts -Value $Display.Subject
    Add-UniqueString -List $hintTexts -Value $Display.Issuer
    Add-UniqueString -List $hintTexts -Value (Get-CertificateCommonName -Subject $Display.Subject)
    Add-UniqueString -List $hintTexts -Value (Get-CertificateCommonName -Subject $Display.Issuer)

    foreach ($chainRow in @($ChainRows)) {
        Add-UniqueString -List $hintTexts -Value $chainRow.Subject
        Add-UniqueString -List $hintTexts -Value $chainRow.Issuer
        Add-UniqueString -List $hintTexts -Value (Get-CertificateCommonName -Subject $chainRow.Subject)
        Add-UniqueString -List $hintTexts -Value (Get-CertificateCommonName -Subject $chainRow.Issuer)
    }

    $normalizedHints = New-Object System.Collections.Generic.List[string]
    $hintTokens = New-Object System.Collections.Generic.List[string]

    foreach ($hint in $hintTexts) {
        $normalized = Convert-ToCaiComparableText -Text $hint
        if ($normalized.Length -ge 8 -and -not $normalizedHints.Contains($normalized)) {
            $normalizedHints.Add($normalized) | Out-Null
        }

        foreach ($token in @(Get-CaiUsefulTokens -Text $hint)) {
            if (-not $hintTokens.Contains($token)) { $hintTokens.Add($token) | Out-Null }
        }
    }

    foreach ($entry in @($VersionEntries)) {
        $reason = ''
        $exactActiveFile = $false
        $entryFileLower = ([string]$entry.FileName).ToLowerInvariant()

        if ($activeFileLookup.ContainsKey($entryFileLower)) {
            $exactActiveFile = $true
            $reason = 'Current CAB file is mentioned in version.txt'
        }
        else {
            foreach ($hint in $normalizedHints) {
                if ([string]::IsNullOrWhiteSpace($hint)) { continue }
                if ($entry.Normalized.Contains($hint) -or $hint.Contains($entry.Normalized)) {
                    $reason = 'Filename resembles EK issuer or chain subject'
                    break
                }
            }

            if ([string]::IsNullOrWhiteSpace($reason)) {
                $entryTokens = @(Get-CaiUsefulTokens -Text $entry.FileName)
                $matchCount = 0
                foreach ($entryToken in $entryTokens) {
                    if ($hintTokens.Contains($entryToken)) { $matchCount++ }
                }

                if ($matchCount -ge 3) {
                    $reason = "Filename shares $matchCount useful token(s) with the EK issuer or chain"
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($reason)) {
            $matchesList.Add([PSCustomObject]@{
                Action          = $entry.Action
                Group           = $entry.Group
                Date            = $entry.Date
                FileName        = $entry.FileName
                Reason          = $reason
                ExactActiveFile = $exactActiveFile
            }) | Out-Null
        }
    }

    return $matchesList.ToArray()
}

function Format-CaiHistorySummary {
    param(
        [Parameter(Mandatory = $true)]$HistoryMatches
    )

    $added = @($HistoryMatches | Where-Object { $_.Action -eq 'Added' })
    $removed = @($HistoryMatches | Where-Object { $_.Action -eq 'Removed' })

    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        return 'Not mentioned in changelog'
    }

    $parts = New-Object System.Collections.Generic.List[string]
    if ($added.Count -gt 0) { $parts.Add("Added: $($added.Count)") | Out-Null }
    if ($removed.Count -gt 0) { $parts.Add("Removed: $($removed.Count)") | Out-Null }

    return ($parts -join '; ')
}

function Get-MicrosoftTpmCaiPackage {
    param(
        [string]$Url = 'https://go.microsoft.com/fwlink/?linkid=2097925'
    )

    $baseFolder = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
    if (-not (Test-Path $baseFolder)) {
        New-Item -Path $baseFolder -ItemType Directory -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $workFolder = Join-Path $baseFolder "Microsoft_TPM_CAI_$stamp"
    $extractFolder = Join-Path $workFolder 'Extracted'
    New-Item -Path $extractFolder -ItemType Directory -Force | Out-Null

    $cabPath = Join-Path $workFolder 'Microsoft_TPM_CAI.cab'

    # Download async so the UI thread stays free and the spinner keeps spinning
    Update-ProgressWindow -Message 'Downloading Microsoft TrustedTPM CAB...' -Detail "Source: $Url"
    $wc = New-Object System.Net.WebClient
    $downloadDone   = $false
    $downloadError  = $null

    $wc.add_DownloadFileCompleted({
        param($s, $e)
        $script:_cabDownloadError = $e.Error
        $script:_cabDownloadDone  = $true
    })
    $script:_cabDownloadDone  = $false
    $script:_cabDownloadError = $null

    $wc.DownloadFileAsync([Uri]$Url, $cabPath)

    $deadline = (Get-Date).AddSeconds(120)
    while (-not $script:_cabDownloadDone -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
        [System.Windows.Forms.Application]::DoEvents()
    }
    $wc.Dispose()

    if (-not $script:_cabDownloadDone) {
        throw 'TrustedTPM CAB download timed out after 120 seconds.'
    }
    if ($script:_cabDownloadError) {
        throw "TrustedTPM CAB download failed: $($script:_cabDownloadError.Message)"
    }
    if (-not (Test-Path $cabPath)) {
        throw 'TrustedTPM CAB file was not created after download.'
    }

    # Extract via Invoke-ProcessHidden so the UI thread stays free
    Update-ProgressWindow -Message 'Extracting TrustedTPM CAB...' -Detail "Extracting to $extractFolder"
    $expand = Join-Path $env:SystemRoot 'System32\expand.exe'
    if (-not (Test-Path $expand)) {
        throw 'expand.exe was not found. Cannot extract the TrustedTPM CAB file.'
    }

    $expandResult = Invoke-ProcessHidden -FilePath $expand -Arguments "-F:* `"$cabPath`" `"$extractFolder`"" -TimeoutSeconds 60
    if ($expandResult.ExitCode -ne 0) {
        throw "CAB extraction failed with exit code $($expandResult.ExitCode). $($expandResult.Output) $($expandResult.Error)"
    }

    Update-ProgressWindow -Message 'Parsing TrustedTPM CAB contents...' -Detail 'Reading version.txt and certificate files.'
    $versionFile = Get-ChildItem -Path $extractFolder -Recurse -File -Filter 'version.txt' -ErrorAction SilentlyContinue | Select-Object -First 1
    $versionText = ''
    if ($versionFile) {
        try {
            $versionText = (Get-Content -Path $versionFile.FullName -Raw -ErrorAction Stop).Trim()
        }
        catch {
            $versionText = "version.txt found but could not be read: $($_.Exception.Message)"
        }
    }
    else {
        $versionText = 'version.txt was not found in the CAB.'
    }

    $versionEntries = @(Get-MicrosoftTpmCaiVersionEntries -VersionText $versionText)

    $certItems = New-Object System.Collections.Generic.List[object]
    $candidateFiles = @(Get-ChildItem -Path $extractFolder -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -ne 'version.txt' -and $_.Length -gt 0
    })

    $fileCount = $candidateFiles.Count
    $fileIndex  = 0
    foreach ($file in $candidateFiles) {
        $fileIndex++
        if ($fileIndex % 20 -eq 0) {
            Update-ProgressWindow -Message 'Parsing TrustedTPM CAB contents...' -Detail "Parsing certificate file $fileIndex of $fileCount..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        foreach ($item in @(Import-CertificatesFromFile -File $file)) {
            if ($null -ne $item.Certificate) {
                $certItems.Add($item) | Out-Null
            }
        }
    }

    return [PSCustomObject]@{
        Url               = $Url
        WorkFolder        = $workFolder
        CabPath           = $cabPath
        ExtractedPath     = $extractFolder
        VersionText       = $versionText
        VersionEntries    = $versionEntries
        VersionEntryCount = $versionEntries.Count
        CertificateItems  = $certItems.ToArray()
        CertificateCount  = $certItems.Count
    }
}


function Get-CachedMicrosoftTpmCaiPackage {
    param(
        [switch]$ForceRefresh
    )

    if ($ForceRefresh -or $null -eq $script:TrustedTpmPackageCache) {
        $script:TrustedTpmPackageCache = Get-MicrosoftTpmCaiPackage
    }

    return $script:TrustedTpmPackageCache
}

function Get-AikAuthorityHintsFromText {
    param(
        [AllowNull()][string]$Text
    )

    $hints = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $hints.ToArray() }

    $patterns = @(
        '(?i)(?<Full>(?:eus|wus|ncu|cus|neu|weu|sea|eas)[\-.]?(?<Key>[a-z0-9]{2,8}[\-.]?keyid[\-.]?[a-f0-9]{12,}))',
        '(?i)(?<Key>[a-z0-9]{2,8}[\-.]?keyid[\-.]?[a-f0-9]{12,})'
    )

    foreach ($pattern in $patterns) {
        foreach ($match in [regex]::Matches($Text, $pattern)) {
            $keyRaw = ''
            $fullRaw = ''

            if ($match.Groups['Key'].Success) { $keyRaw = $match.Groups['Key'].Value }
            if ($match.Groups['Full'].Success) { $fullRaw = $match.Groups['Full'].Value }
            if ([string]::IsNullOrWhiteSpace($fullRaw)) { $fullRaw = $keyRaw }

            if ([string]::IsNullOrWhiteSpace($keyRaw)) { continue }

            $key = (($keyRaw.ToLowerInvariant()) -replace '\.', '-')
            $full = (($fullRaw.ToLowerInvariant()) -replace '\.', '-')
            $normalizedKey = Convert-ToCaiComparableText -Text $key
            $normalizedFull = Convert-ToCaiComparableText -Text $full

            $exists = $false
            foreach ($hint in $hints) {
                if ($hint.NormalizedKey -eq $normalizedKey) {
                    $exists = $true
                    break
                }
            }

            if (-not $exists) {
                $hints.Add([PSCustomObject]@{
                    KeyId          = $key
                    FullKeyId      = $full
                    NormalizedKey  = $normalizedKey
                    NormalizedFull = $normalizedFull
                }) | Out-Null
            }
        }
    }

    return $hints.ToArray()
}

function Test-AikAuthorityAgainstTrustedTpmCab {
    param(
        [AllowNull()][string]$Text,
        [AllowNull()]$Urls,
        [string]$Category = 'AIK'
    )

    try {
        $combined = New-Object System.Text.StringBuilder
        if (-not [string]::IsNullOrWhiteSpace($Text)) { [void]$combined.AppendLine($Text) }
        foreach ($url in @($Urls)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$url)) { [void]$combined.AppendLine([string]$url) }
        }

        $hints = @(Get-AikAuthorityHintsFromText -Text $combined.ToString())
        if ($hints.Count -eq 0) {
            Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'WARN' -Result 'No KeyId found' -Details 'No microsoftaik KeyId could be parsed from the certreq output.' -Remediation 'Open the AIK test output and check if certreq returned the AIK CA authority URL.'
            return
        }

        Update-ProgressWindow -Message 'Downloading Microsoft TrustedTPM CAB...' -Detail 'Fetching https://go.microsoft.com/fwlink/?linkid=2097925 to validate AIK CA authority.'
        $package = Get-CachedMicrosoftTpmCaiPackage
        $activeFileNames = @($package.CertificateItems | ForEach-Object { [string]$_.FileName })
        $versionEntries = @($package.VersionEntries)

        foreach ($hint in $hints) {
            $activeMatches = New-Object System.Collections.Generic.List[string]
            foreach ($fileName in $activeFileNames) {
                $normalizedFile = Convert-ToCaiComparableText -Text $fileName
                if ($normalizedFile.Contains($hint.NormalizedFull) -or $normalizedFile.Contains($hint.NormalizedKey)) {
                    Add-UniqueString -List $activeMatches -Value $fileName
                }
            }

            $historyMatches = New-Object System.Collections.Generic.List[object]
            foreach ($entry in $versionEntries) {
                $entryText = Convert-ToCaiComparableText -Text $entry.FileName
                if ($entryText.Contains($hint.NormalizedFull) -or $entryText.Contains($hint.NormalizedKey)) {
                    $historyMatches.Add($entry) | Out-Null
                }
            }

            $added = @($historyMatches | Where-Object { $_.Action -eq 'Added' })
            $removed = @($historyMatches | Where-Object { $_.Action -eq 'Removed' })
            $addedText = (($added | Select-Object -ExpandProperty FileName -Unique) -join '; ')
            $removedText = (($removed | Select-Object -ExpandProperty FileName -Unique) -join '; ')
            $activeText = (($activeMatches.ToArray() | Select-Object -Unique) -join '; ')

            if ($activeMatches.Count -gt 0) {
                Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'PASS' -Result 'Active AIK CA match' -Details "KeyId $($hint.KeyId) was found as active certificate file(s) in the current TrustedTPM CAB: $activeText. version.txt added: $addedText. version.txt removed: $removedText."
            }
            elseif ($removed.Count -gt 0) {
                Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'FAIL' -Result 'Removed AIK CA' -Details "KeyId $($hint.KeyId) was found under removed entries in version.txt: $removedText." -Remediation 'The AIK authority appears to be withdrawn in the TrustedTPM package. Check TPM firmware with the OEM or Microsoft support.'
            }
            elseif ($added.Count -gt 0) {
                Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'PASS' -Result 'Added in version.txt' -Details "KeyId $($hint.KeyId) was found under added entries in version.txt and no removed entry was found: $addedText."
            }
            else {
                Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'WARN' -Result 'Not in TrustedTPM CAB' -Details "KeyId $($hint.KeyId) was not found in active CAB files or version.txt." -Remediation 'If certreq also fails, this can point to an AIK CA authority that is not published in the current TrustedTPM package.'
            }
        }
    }
    catch {
        Add-Result -Category $Category -Check 'AIK TrustedTPM CAB lookup' -Status 'WARN' -Result 'Lookup failed' -Details $_.Exception.Message -Remediation 'Check internet access to the TrustedTPM CAB URL and retry the AIK test.'
    }
}

function Test-EkCertificatesAgainstMicrosoftCai {
    param(
        [Parameter(Mandatory = $true)]$CertificateItems
    )

    Start-ProgressWindow -Title 'Checking Microsoft TrustedTPM CAB' -Maximum 5 -Message 'Downloading Microsoft TrustedTPM CAB...'

    try {
        Update-ProgressWindow -Message 'Downloading Microsoft TrustedTPM CAB' -Detail 'Using https://go.microsoft.com/fwlink/?linkid=2097925.' -Step
        $package = Get-CachedMicrosoftTpmCaiPackage

        Update-ProgressWindow -Message 'Reading version.txt' -Detail "version.txt entries parsed: $($package.VersionEntryCount)." -Step
        if ($package.CertificateCount -gt 0) {
            Add-Result -Category 'EK CAI' -Check 'Microsoft TrustedTPM CAB' -Status 'PASS' -Result "Active certs: $($package.CertificateCount)" -Details "CAB extracted. Active certificate files parsed: $($package.CertificateCount). version.txt changelog entries parsed: $($package.VersionEntryCount)."
        }
        else {
            Add-Result -Category 'EK CAI' -Check 'Microsoft TrustedTPM CAB' -Status 'WARN' -Result 'No active certs parsed' -Details "CAB extracted and version.txt was read, but no active certificate files could be parsed. Extracted folder: $($package.ExtractedPath)." -Remediation 'Open the extracted folder and inspect the CAB contents manually.'
        }

        Update-ProgressWindow -Message 'Building CAI lookup table' -Detail 'Indexing active certificate files from the CAB.' -Step
        $caiThumbprints = @{}
        $caiSubjects = @{}
        $caiRows = New-Object System.Collections.Generic.List[object]

        foreach ($item in @($package.CertificateItems)) {
            try {
                $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type 'Microsoft TrustedTPM'
                if (-not [string]::IsNullOrWhiteSpace($display.Thumbprint)) {
                    Add-CaiLookupValue -Table $caiThumbprints -Key $display.Thumbprint.ToUpperInvariant() -Value $item.FileName
                }
                if (-not [string]::IsNullOrWhiteSpace($display.Subject)) {
                    Add-CaiLookupValue -Table $caiSubjects -Key $display.Subject -Value $item.FileName
                }
                $caiRows.Add([PSCustomObject]@{
                    SourceFile  = $item.FileName
                    Thumbprint  = $display.Thumbprint
                    Subject     = $display.Subject
                    Issuer      = $display.Issuer
                    NotAfter    = $display.NotAfter
                }) | Out-Null
            }
            catch { }
        }

        Update-ProgressWindow -Message 'Comparing EK certificates' -Detail 'Checking active CAB certs first and using version.txt only as changelog context.' -Step
        $validationRows = New-Object System.Collections.Generic.List[object]
        $allEkCerts = @($CertificateItems | ForEach-Object { $_.Certificate })

        foreach ($item in @($CertificateItems)) {
            try {
                $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type
                $issuerMatch = $false
                $issuerActiveFiles = New-Object System.Collections.Generic.List[string]

                if (-not [string]::IsNullOrWhiteSpace($display.Issuer) -and $caiSubjects.ContainsKey($display.Issuer)) {
                    $issuerMatch = $true
                    foreach ($sourceFile in @($caiSubjects[$display.Issuer].ToArray())) {
                        Add-UniqueString -List $issuerActiveFiles -Value $sourceFile
                    }
                }

                $chainRows = @(Get-CertificateChainReport -Certificate $item.Certificate -AllCertificates $allEkCerts)
                $matchingChainThumbprints = New-Object System.Collections.Generic.List[string]
                $activeSourceFiles = New-Object System.Collections.Generic.List[string]

                foreach ($sourceFile in @($issuerActiveFiles.ToArray())) {
                    Add-UniqueString -List $activeSourceFiles -Value $sourceFile
                }

                foreach ($chainRow in $chainRows) {
                    # The TrustedTPM CAB is expected to contain TPM vendor root/intermediate CA certificates.
                    # It normally does not contain the per-device EK leaf certificate, so skip chain level 0 here.
                    if ($chainRow.Level -eq 0) { continue }

                    if (-not [string]::IsNullOrWhiteSpace($chainRow.Thumbprint)) {
                        $thumb = $chainRow.Thumbprint.ToUpperInvariant()
                        if ($caiThumbprints.ContainsKey($thumb)) {
                            Add-UniqueString -List $matchingChainThumbprints -Value $chainRow.Thumbprint
                            foreach ($sourceFile in @($caiThumbprints[$thumb].ToArray())) {
                                Add-UniqueString -List $activeSourceFiles -Value $sourceFile
                            }
                        }
                    }
                }

                $historyMatches = @(Get-CaiVersionHistoryMatches -VersionEntries $package.VersionEntries -Display $display -ChainRows $chainRows -ActiveSourceFiles $activeSourceFiles.ToArray())
                $removedHistory = @($historyMatches | Where-Object { $_.Action -eq 'Removed' })
                $addedHistory = @($historyMatches | Where-Object { $_.Action -eq 'Added' })
                $historySummary = Format-CaiHistorySummary -HistoryMatches $historyMatches
                $removedHistoryFiles = (($removedHistory | Select-Object -ExpandProperty FileName -Unique) -join '; ')
                $addedHistoryFiles = (($addedHistory | Select-Object -ExpandProperty FileName -Unique) -join '; ')
                $activeSourceText = (($activeSourceFiles.ToArray() | Select-Object -Unique) -join '; ')

                $activeMatch = ($issuerMatch -or $matchingChainThumbprints.Count -gt 0)
                $status = 'WARN'
                $result = 'No active EK CA match'
                $details = "No active root or intermediate CA certificate file in the current TrustedTPM CAB matched the EK issuer or chain. EK issuer: $($display.Issuer)."
                $remediation = 'Check whether the manufacturer CAI URL was removed from the current CAB or whether this TPM vendor uses a chain Windows cannot map automatically.'

                if ($activeMatch) {
                    $status = 'PASS'
                    $result = 'Active EK CA match'
                    $details = "Current CAB match found. Matching EK issuer/chain CA file(s): $activeSourceText. version.txt is only a changelog. History: $historySummary."
                    $remediation = ''
                }
                elseif ($removedHistory.Count -gt 0) {
                    $status = 'WARN'
                    $result = 'Removed in version.txt'
                    $details = "No active TrustedTPM CA certificate file matched, but version.txt has removed entry candidate(s): $removedHistoryFiles. Removed entries are historical and are not active TrustedTPM CA files."
                    $remediation = 'Treat this as removed from the current TrustedTPM package unless another active certificate file matches the EK chain.'
                }

                Add-Result -Category 'EK CAI' -Check "$($item.Type) EK certificate" -Status $status -Result $result -Details $details -Remediation $remediation

                $validationRows.Add([PSCustomObject]@{
                    Type                     = $item.Type
                    Result                   = $result
                    ActiveInCurrentCab        = $activeMatch
                    VersionTxtStatus          = $historySummary
                    Thumbprint               = $display.Thumbprint
                    Subject                  = $display.Subject
                    Issuer                   = $display.Issuer
                    IssuerFoundInActiveCai    = $issuerMatch
                    MatchingChainThumbprints  = ($matchingChainThumbprints -join '; ')
                    ActiveCaiFiles            = $activeSourceText
                    AddedHistoryFiles         = $addedHistoryFiles
                    RemovedHistoryFiles       = $removedHistoryFiles
                    CaiVersionEntryCount      = $package.VersionEntryCount
                    ExtractedPath             = $package.ExtractedPath
                }) | Out-Null
            }
            catch {
                Add-Result -Category 'EK CAI' -Check "$($item.Type) EK certificate" -Status 'WARN' -Result 'Check failed' -Details $_.Exception.Message -Remediation 'Export TPM logs and inspect the EK certificate manually.'
            }
        }

        Update-ProgressWindow -Message 'Opening CAI result window' -Detail 'Showing validation result.' -Step
        Close-ProgressWindow

        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Microsoft TrustedTPM CAB validation'
        $form.ClientSize = New-Object System.Drawing.Size(1260, 620)
        $form.StartPosition = 'CenterParent'
        $form.MinimumSize = New-Object System.Drawing.Size(1040, 460)
        $form.BackColor = [System.Drawing.Color]::White

        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 4
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 78)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 150)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 48)) | Out-Null
        $form.Controls.Add($layout)

        $label = New-Object System.Windows.Forms.Label
        $label.Dock = 'Fill'
        $label.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 4)
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $label.Text = "Microsoft TrustedTPM CAB. Active certificate files parsed: $($package.CertificateCount). version.txt changelog entries parsed: $($package.VersionEntryCount). Removed entries in version.txt are historical and are not treated as active TrustedTPM CA certificates."
        $layout.Controls.Add($label, 0, 0)

        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.ReadOnly = $true
        $grid.SelectionMode = 'FullRowSelect'
        $grid.MultiSelect = $false
        $grid.RowHeadersVisible = $false
        $grid.AutoSizeColumnsMode = 'None'
        $grid.ScrollBars = 'Both'
        $grid.BackgroundColor = [System.Drawing.Color]::White
        $grid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $grid.Columns.Add('Type', 'Type') | Out-Null
        $grid.Columns.Add('Result', 'Result') | Out-Null
        $grid.Columns.Add('ActiveInCurrentCab', 'EK issuer/chain CA in active CAB') | Out-Null
        $grid.Columns.Add('VersionTxtStatus', 'version.txt changelog') | Out-Null
        $grid.Columns.Add('Thumbprint', 'Thumbprint') | Out-Null
        $grid.Columns.Add('IssuerFoundInActiveCai', 'EK issuer in active CAB') | Out-Null
        $grid.Columns.Add('MatchingChainThumbprints', 'Matching CA thumbprints') | Out-Null
        $grid.Columns.Add('ActiveCaiFiles', 'Active EK CA file(s)') | Out-Null
        $grid.Columns.Add('RemovedHistoryFiles', 'Removed history file(s)') | Out-Null
        $grid.Columns.Add('Subject', 'Subject') | Out-Null
        $grid.Columns.Add('Issuer', 'Issuer') | Out-Null
        $grid.Columns['Type'].Width = 110
        $grid.Columns['Result'].Width = 160
        $grid.Columns['ActiveInCurrentCab'].Width = 140
        $grid.Columns['VersionTxtStatus'].Width = 160
        $grid.Columns['Thumbprint'].Width = 300
        $grid.Columns['IssuerFoundInActiveCai'].Width = 140
        $grid.Columns['MatchingChainThumbprints'].Width = 360
        $grid.Columns['ActiveCaiFiles'].Width = 360
        $grid.Columns['RemovedHistoryFiles'].Width = 360
        $grid.Columns['Subject'].Width = 440
        $grid.Columns['Issuer'].Width = 440

        foreach ($row in $validationRows) {
            $idx = $grid.Rows.Add(
                $row.Type,
                $row.Result,
                $row.ActiveInCurrentCab,
                $row.VersionTxtStatus,
                $row.Thumbprint,
                $row.IssuerFoundInActiveCai,
                $row.MatchingChainThumbprints,
                $row.ActiveCaiFiles,
                $row.RemovedHistoryFiles,
                $row.Subject,
                $row.Issuer
            )
            if ($row.Result -eq 'Active EK CA match') {
                $grid.Rows[$idx].DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
            }
            elseif ($row.Result -eq 'Removed in version.txt') {
                $grid.Rows[$idx].DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
            }
            else {
                $grid.Rows[$idx].DefaultCellStyle.BackColor = [System.Drawing.Color]::LemonChiffon
            }
        }
        $layout.Controls.Add($grid, 0, 1)

        $details = New-Object System.Windows.Forms.TextBox
        $details.Dock = 'Fill'
        $details.Multiline = $true
        $details.ReadOnly = $true
        $details.ScrollBars = 'Both'
        $details.WordWrap = $false
        $details.Font = New-Object System.Drawing.Font('Consolas', 9)
        $details.Text = @(
            "CAB URL: $($package.Url)",
            "CAB file: $($package.CabPath)",
            "Extracted folder: $($package.ExtractedPath)",
            "Active certificate files parsed: $($package.CertificateCount)",
            "version.txt changelog entries parsed: $($package.VersionEntryCount)",
            '',
            'Important:',
            'version.txt is a changelog. It is normal when an active CAB CA match is not mentioned there.',
            'For EK validation the tool checks the EK issuer and CA chain against the active root/intermediate CA certificates in the current TrustedTPM package. The per-device EK leaf certificate is normally not expected inside the CAB.',
            'A removed entry in version.txt means historical context, not a current active TrustedTPM CA certificate.',
            '',
            'version.txt preview:',
            (($package.VersionText -split "`r`n|`n|`r" | Select-Object -First 60) -join [Environment]::NewLine)
        ) -join [Environment]::NewLine
        $layout.Controls.Add($details, 0, 2)

        $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $buttonPanel.Dock = 'Fill'
        $buttonPanel.FlowDirection = 'RightToLeft'
        $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)
        $layout.Controls.Add($buttonPanel, 0, 3)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = 'Close'
        $closeButton.Width = 90
        $closeButton.Height = 28
        $buttonPanel.Controls.Add($closeButton)
        $closeButton.Add_Click({ $form.Close() })

        $openButton = New-Object System.Windows.Forms.Button
        $openButton.Text = 'Open CAB folder'
        $openButton.Width = 130
        $openButton.Height = 28
        $buttonPanel.Controls.Add($openButton)
        $openButton.Add_Click({ Start-Process explorer.exe -ArgumentList "`"$($package.ExtractedPath)`"" })

        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Text = 'Copy'
        $copyButton.Width = 90
        $copyButton.Height = 28
        $buttonPanel.Controls.Add($copyButton)
        $copyButton.Add_Click({
            $text = @(
                $details.Text,
                '',
                ($validationRows | Format-Table Type, Result, ActiveInCurrentCab, VersionTxtStatus, ActiveCaiFiles, RemovedHistoryFiles -AutoSize | Out-String).Trim()
            ) -join [Environment]::NewLine
            [System.Windows.Forms.Clipboard]::SetText($text)
        })

        [void]$form.ShowDialog()
    }
    catch {
        Close-ProgressWindow
        Add-Result -Category 'EK CAI' -Check 'Microsoft TrustedTPM CAB' -Status 'WARN' -Result 'Download or parse failed' -Details $_.Exception.Message -Remediation 'Check internet access and try again.'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Microsoft TrustedTPM CAB validation failed', 'OK', 'Warning') | Out-Null
    }
    finally {
        Close-ProgressWindow
    }
}


function Get-CertificateChainReport {
    param(
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)]$AllCertificates
    )

    $report = New-Object System.Collections.Generic.List[object]

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

    foreach ($extra in @($AllCertificates)) {
        try {
            if ($null -ne $extra -and $extra.Thumbprint -ne $Certificate.Thumbprint) {
                [void]$chain.ChainPolicy.ExtraStore.Add($extra)
            }
        }
        catch { }
    }

    $built = $false
    $buildStatus = ''

    try {
        $built = $chain.Build($Certificate)
        if ($chain.ChainStatus.Count -eq 0) {
            $buildStatus = 'OK'
        }
        else {
            $statusItems = New-Object System.Collections.Generic.List[string]
            foreach ($status in $chain.ChainStatus) {
                $text = ([string]$status.StatusInformation).Trim()
                if ([string]::IsNullOrWhiteSpace($text)) {
                    $text = [string]$status.Status
                }
                else {
                    $text = "$($status.Status): $text"
                }
                $statusItems.Add($text) | Out-Null
            }
            $buildStatus = ($statusItems -join '; ')
        }
    }
    catch {
        $buildStatus = $_.Exception.Message
    }

    $level = 0
    foreach ($element in $chain.ChainElements) {
        try {
            $cert = $element.Certificate
            $display = Convert-CertificateForDisplay -Certificate $cert -Type 'Chain'
            $report.Add([PSCustomObject]@{
                Level              = $level
                ChainBuildSucceeded = $built
                OverallStatus      = $buildStatus
                ElementStatus      = Get-CertificateChainStatusText -ChainElement $element
                Thumbprint         = $display.Thumbprint
                Subject            = $display.Subject
                Issuer             = $display.Issuer
                SerialNumber       = $display.SerialNumber
                NotBefore          = $display.NotBefore
                NotAfter           = $display.NotAfter
                SignatureAlgorithm = $display.SignatureAlgorithm
                PublicKeyAlgorithm = $display.PublicKeyAlgorithm
                KeySize            = $display.KeySize
                SubjectKeyIdentifier   = $display.SubjectKeyIdentifier
                AuthorityKeyIdentifier = $display.AuthorityKeyIdentifier
                AuthorityInfoAccess    = $display.AuthorityInfoAccess
                IsSelfSigned       = $display.IsSelfSigned
            }) | Out-Null
            $level++
        }
        catch { }
    }

    if ($report.Count -eq 0) {
        $display = Convert-CertificateForDisplay -Certificate $Certificate -Type 'Selected'
        $report.Add([PSCustomObject]@{
            Level              = 0
            ChainBuildSucceeded = $built
            OverallStatus      = $buildStatus
            ElementStatus      = 'No chain elements returned.'
            Thumbprint         = $display.Thumbprint
            Subject            = $display.Subject
            Issuer             = $display.Issuer
            SerialNumber       = $display.SerialNumber
            NotBefore          = $display.NotBefore
            NotAfter           = $display.NotAfter
            SignatureAlgorithm = $display.SignatureAlgorithm
            PublicKeyAlgorithm = $display.PublicKeyAlgorithm
            KeySize            = $display.KeySize
            SubjectKeyIdentifier   = $display.SubjectKeyIdentifier
            AuthorityKeyIdentifier = $display.AuthorityKeyIdentifier
            AuthorityInfoAccess    = $display.AuthorityInfoAccess
            IsSelfSigned       = $display.IsSelfSigned
        }) | Out-Null
    }

    try { $chain.Dispose() } catch { }

    return $report.ToArray()
}


function Get-CertificateVisualSubjectText {
    param(
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        return ''
    }

    if ($Subject -match 'CN=([^,]+)') {
        return $Matches[1].Trim()
    }

    if ($Subject -match 'TPMModel=([^,]+)') {
        $model = $Matches[1].Trim()
        if ($Subject -match 'TPMManufacturer=([^,]+)') {
            return "TPM $model / $($Matches[1].Trim())"
        }
        return "TPM $model"
    }

    if ($Subject.Length -gt 70) {
        return $Subject.Substring(0, 67) + '...'
    }

    return $Subject
}

function New-RoundedRectanglePath {
    param(
        [Parameter(Mandatory = $true)][System.Drawing.Rectangle]$Rectangle,
        [int]$Radius = 16
    )

    $diameter = $Radius * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath

    if ($diameter -le 0) {
        $path.AddRectangle($Rectangle)
        return $path
    }

    $arc = New-Object System.Drawing.Rectangle($Rectangle.X, $Rectangle.Y, $diameter, $diameter)
    $path.AddArc($arc, 180, 90)

    $arc.X = $Rectangle.Right - $diameter
    $path.AddArc($arc, 270, 90)

    $arc.Y = $Rectangle.Bottom - $diameter
    $path.AddArc($arc, 0, 90)

    $arc.X = $Rectangle.X
    $path.AddArc($arc, 90, 90)

    $path.CloseFigure()
    return $path
}


function Get-CertificateCommonNameFromSubject {
    param(
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        return ''
    }

    if ($Subject -match 'CN=([^,]+)') {
        return $Matches[1].Trim()
    }

    return $Subject
}

function Get-NormalizedCertificateKeyIdentifier {
    param(
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $matches = [regex]::Matches($Text, '[A-Fa-f0-9]{2}(?::[A-Fa-f0-9]{2}){3,}|[A-Fa-f0-9]{16,}')
    if ($matches.Count -eq 0) {
        return ''
    }

    $best = ''
    foreach ($match in $matches) {
        $candidate = ([string]$match.Value -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
        if ($candidate.Length -gt $best.Length) {
            $best = $candidate
        }
    }

    return $best
}

function Invoke-AsyncWebDownload {
    # Downloads bytes from a URL asynchronously, pumping DoEvents so the spinner keeps spinning.
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [int]$TimeoutSeconds = 30
    )

    $script:_asyncBytes = $null
    $script:_asyncError = $null
    $script:_asyncDone  = $false

    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'AutopilotTpmAttestationTool/0.24')

    $wc.add_DownloadDataCompleted({
        param($s, $e)
        $script:_asyncError = $e.Error
        $script:_asyncBytes = $e.Result
        $script:_asyncDone  = $true
    })

    $wc.DownloadDataAsync([Uri]$Url)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while (-not $script:_asyncDone -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 50
        [System.Windows.Forms.Application]::DoEvents()
    }
    $wc.Dispose()

    if (-not $script:_asyncDone) { throw "Download timed out after $TimeoutSeconds seconds: $Url" }
    if ($script:_asyncError)     { throw "Download failed: $($script:_asyncError.Message) - $Url" }
    return $script:_asyncBytes
}

function Install-CertificateIntoStore {
    param(
        [Parameter(Mandatory=$true)]$Certificate,
        [Parameter(Mandatory=$true)][string]$StoreName,   # e.g. 'Root' or 'CertificateAuthority'
        [string]$StoreLocation = 'LocalMachine'
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $StoreName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($Certificate)
    $store.Close()
}

function Invoke-DownloadAndInstallMissingCACerts {
    # Walks up the issuer chain from the given starting certs by following AIA CA Issuers URLs.
    # Installs intermediates into LocalMachine\CA and roots into LocalMachine\Root.
    param(
        [Parameter(Mandatory=$true)]$StartingCertificates,   # array of X509Certificate2
        [int]$MaxDepth = 6
    )

    $installed   = New-Object System.Collections.Generic.List[object]
    $failed      = New-Object System.Collections.Generic.List[string]
    $seenThumbs  = New-Object 'System.Collections.Generic.HashSet[string]'
    $seenUrls    = New-Object 'System.Collections.Generic.HashSet[string]'

    # Seed with certs we already have
    foreach ($c in $StartingCertificates) {
        if ($c -and $c.Thumbprint) { [void]$seenThumbs.Add($c.Thumbprint) }
    }

    # Queue of certs whose AIA we still need to follow
    $queue = New-Object System.Collections.Generic.Queue[System.Security.Cryptography.X509Certificates.X509Certificate2]
    foreach ($c in $StartingCertificates) { if ($c) { $queue.Enqueue($c) } }

    $depth = 0
    while ($queue.Count -gt 0 -and $depth -lt $MaxDepth) {
        $depth++
        $current = $queue.Dequeue()

        # Extract AIA CA Issuers URLs from this cert
        $aiaUrls = New-Object System.Collections.Generic.List[string]
        try {
            foreach ($ext in $current.Extensions) {
                if ($ext.Oid.Value -eq '1.3.6.1.5.5.7.1.1') {
                    $aiaText = $ext.Format($true)
                    $urlMatches = [regex]::Matches($aiaText, 'https?://[^\s\r\n]+')
                    foreach ($m in $urlMatches) {
                        $u = $m.Value.Trim()
                        if ($u -and -not $aiaUrls.Contains($u)) { $aiaUrls.Add($u) | Out-Null }
                    }
                }
            }
        } catch { }

        foreach ($url in $aiaUrls) {
            if (-not $seenUrls.Add($url)) { continue }

            Update-ProgressWindow -Message 'Downloading issuer certificate...' -Detail $url

            try {
                $bytes = Invoke-AsyncWebDownload -Url $url -TimeoutSeconds 25
                $certs = @(Get-CertificateObjectsFromBytes -Bytes $bytes)

                foreach ($cert in $certs) {
                    if (-not $cert -or [string]::IsNullOrWhiteSpace($cert.Thumbprint)) { continue }
                    if (-not $seenThumbs.Add($cert.Thumbprint)) { continue }

                    $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                    $storeName    = if ($isSelfSigned) { 'Root' } else { 'CertificateAuthority' }
                    $storeLabel   = if ($isSelfSigned) { 'LocalMachine\Root (Trusted Root CA)' } else { 'LocalMachine\CA (Intermediate CA)' }

                    try {
                        Install-CertificateIntoStore -Certificate $cert -StoreName $storeName
                        $installed.Add([PSCustomObject]@{
                            Thumbprint = $cert.Thumbprint
                            Subject    = $cert.Subject
                            Store      = $storeLabel
                            SourceUrl  = $url
                            IsSelfSigned = $isSelfSigned
                        }) | Out-Null
                        Add-Result -Category 'EK Chain' -Check 'CA cert installed' -Status 'PASS' `
                            -Details "Installed into $storeLabel. Thumbprint: $($cert.Thumbprint). Subject: $($cert.Subject). Source: $url"
                    }
                    catch {
                        $failed.Add("$($cert.Subject): $($_.Exception.Message)") | Out-Null
                        Add-Result -Category 'EK Chain' -Check 'CA cert install failed' -Status 'FAIL' `
                            -Details "$($cert.Subject): $($_.Exception.Message)" `
                            -Remediation 'Run the tool as administrator to install into LocalMachine stores.'
                    }

                    # If not self-signed, queue it so we can walk further up
                    if (-not $isSelfSigned) { $queue.Enqueue($cert) }
                }
            }
            catch {
                $failed.Add("$url : $($_.Exception.Message)") | Out-Null
                Add-Result -Category 'EK Chain' -Check 'CA cert download failed' -Status 'WARN' `
                    -Details "$url : $($_.Exception.Message)" `
                    -Remediation 'Check internet connectivity and retry.'
            }
        }

        # If current has no AIA and is not self-signed we have hit the top of what AIA can reach
    }

    return [PSCustomObject]@{
        Installed = $installed.ToArray()
        Failed    = $failed.ToArray()
    }
}

function Get-CertificateAiaCaIssuerUrlsFromText {
    param(
        [string]$AuthorityInfoAccess
    )

    $urls = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($AuthorityInfoAccess)) {
        return $urls.ToArray()
    }

    $matches = [regex]::Matches($AuthorityInfoAccess, 'https?://[^\s,;\)]+')
    foreach ($match in $matches) {
        $value = ([string]$match.Value).Trim()
        if (-not [string]::IsNullOrWhiteSpace($value) -and -not $urls.Contains($value)) {
            $urls.Add($value) | Out-Null
        }
    }

    return $urls.ToArray()
}


function Get-CertificateObjectsFromBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $items = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]

    try {
        $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $collection.Import($Bytes)
        foreach ($cert in $collection) {
            if ($null -ne $cert -and -not [string]::IsNullOrWhiteSpace($cert.Thumbprint)) {
                $items.Add($cert) | Out-Null
            }
        }
    }
    catch { }

    if ($items.Count -eq 0) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $Bytes)
            if ($null -ne $cert -and -not [string]::IsNullOrWhiteSpace($cert.Thumbprint)) {
                $items.Add($cert) | Out-Null
            }
        }
        catch { }
    }

    return $items.ToArray()
}

function Get-AiaIssuerCertificateItemsFromChainRows {
    param(
        [Parameter(Mandatory = $true)]$ChainRows,
        [int]$TimeoutSeconds = 25
    )

    $downloaded = New-Object System.Collections.Generic.List[object]
    $seenUrls = New-Object 'System.Collections.Generic.HashSet[string]'
    $seenThumbprints = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($row in @($ChainRows | Sort-Object -Property Level -Descending)) {
        $aia = ''
        try { $aia = [string]$row.AuthorityInfoAccess } catch { }
        $urls = @(Get-CertificateAiaCaIssuerUrlsFromText -AuthorityInfoAccess $aia)

        foreach ($url in $urls) {
            if ([string]::IsNullOrWhiteSpace($url)) { continue }
            if (-not $seenUrls.Add($url)) { continue }

            try {
                $client = New-Object System.Net.WebClient
                $client.Headers.Add('user-agent', 'Autopilot TPM Attestation Tool')
                $bytes = $client.DownloadData($url)
                $client.Dispose()

                $certs = @(Get-CertificateObjectsFromBytes -Bytes $bytes)
                foreach ($cert in $certs) {
                    if ($null -eq $cert -or [string]::IsNullOrWhiteSpace($cert.Thumbprint)) { continue }
                    if (-not $seenThumbprints.Add([string]$cert.Thumbprint)) { continue }

                    $downloaded.Add([PSCustomObject]@{
                        Type        = 'AIA issuer'
                        Certificate = $cert
                        SourceUrl   = $url
                    }) | Out-Null
                }
            }
            catch {
                $downloaded.Add([PSCustomObject]@{
                    Type        = 'AIA issuer download failed'
                    Certificate = $null
                    SourceUrl   = $url
                    Error       = $_.Exception.Message
                }) | Out-Null
            }
        }
    }

    return $downloaded.ToArray()
}

function Get-UniqueCertificateItems {
    param(
        [Parameter(Mandatory = $true)]$CertificateItems
    )

    $unique = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($item in @($CertificateItems)) {
        try {
            if ($null -eq $item -or $null -eq $item.Certificate) { continue }
            $thumbprint = [string]$item.Certificate.Thumbprint
            if ([string]::IsNullOrWhiteSpace($thumbprint)) { continue }
            if ($seen.Add($thumbprint)) {
                $unique.Add($item) | Out-Null
            }
        }
        catch { }
    }

    return $unique.ToArray()
}

function Find-IssuerCertificateCandidatesFromStores {
    param(
        [Parameter(Mandatory = $true)]$ChainRow
    )

    $candidates = New-Object System.Collections.Generic.List[object]

    $expectedIssuer = ''
    $expectedAuthorityKeyId = ''
    try { $expectedIssuer = [string]$ChainRow.Issuer } catch { }
    try { $expectedAuthorityKeyId = Get-NormalizedCertificateKeyIdentifier -Text ([string]$ChainRow.AuthorityKeyIdentifier) } catch { }

    if ([string]::IsNullOrWhiteSpace($expectedIssuer) -and [string]::IsNullOrWhiteSpace($expectedAuthorityKeyId)) {
        return $candidates.ToArray()
    }

    $stores = @(
        'Cert:\LocalMachine\Root',
        'Cert:\LocalMachine\CA',
        'Cert:\CurrentUser\Root',
        'Cert:\CurrentUser\CA'
    )

    foreach ($store in $stores) {
        try {
            if (-not (Test-Path $store)) {
                continue
            }

            foreach ($cert in @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue)) {
                $display = Convert-CertificateForDisplay -Certificate $cert -Type $store
                $subjectMatch = (-not [string]::IsNullOrWhiteSpace($expectedIssuer) -and ([string]$display.Subject -eq $expectedIssuer))
                $ski = Get-NormalizedCertificateKeyIdentifier -Text ([string]$display.SubjectKeyIdentifier)
                $keyMatch = (-not [string]::IsNullOrWhiteSpace($expectedAuthorityKeyId) -and -not [string]::IsNullOrWhiteSpace($ski) -and $expectedAuthorityKeyId.Contains($ski))

                if ($subjectMatch -or $keyMatch) {
                    $candidates.Add([PSCustomObject]@{
                        Store       = $store
                        Thumbprint  = $display.Thumbprint
                        Subject     = $display.Subject
                        NotAfter    = $display.NotAfter
                        SubjectMatch = $subjectMatch
                        KeyMatch    = $keyMatch
                    }) | Out-Null
                }
            }
        }
        catch { }
    }

    return $candidates.ToArray()
}


function Find-IssuerCertificateCandidatesFromTrustedTpmCab {
    param(
        [Parameter(Mandatory = $true)]$ChainRow
    )

    $candidates = New-Object System.Collections.Generic.List[object]

    $expectedIssuer = ''
    $expectedAuthorityKeyId = ''
    try { $expectedIssuer = [string]$ChainRow.Issuer } catch { }
    try { $expectedAuthorityKeyId = Get-NormalizedCertificateKeyIdentifier -Text ([string]$ChainRow.AuthorityKeyIdentifier) } catch { }

    if ([string]::IsNullOrWhiteSpace($expectedIssuer) -and [string]::IsNullOrWhiteSpace($expectedAuthorityKeyId)) {
        return $candidates.ToArray()
    }

    try {
        $package = Get-CachedMicrosoftTpmCaiPackage

        foreach ($item in @($package.CertificateItems)) {
            try {
                if ($null -eq $item.Certificate) { continue }

                $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type 'TrustedTPM CAB'
                $subjectMatch = (-not [string]::IsNullOrWhiteSpace($expectedIssuer) -and ([string]$display.Subject -eq $expectedIssuer))
                $ski = Get-NormalizedCertificateKeyIdentifier -Text ([string]$display.SubjectKeyIdentifier)
                $keyMatch = (-not [string]::IsNullOrWhiteSpace($expectedAuthorityKeyId) -and -not [string]::IsNullOrWhiteSpace($ski) -and $expectedAuthorityKeyId.Contains($ski))

                if ($subjectMatch -or $keyMatch) {
                    $candidates.Add([PSCustomObject]@{
                        FileName     = [string]$item.FileName
                        Thumbprint   = $display.Thumbprint
                        Subject      = $display.Subject
                        Issuer       = $display.Issuer
                        NotAfter     = $display.NotAfter
                        IsSelfSigned = $display.IsSelfSigned
                        SubjectMatch = $subjectMatch
                        KeyMatch     = $keyMatch
                        IsError      = $false
                        Error        = ''
                    }) | Out-Null
                }
            }
            catch { }
        }
    }
    catch {
        $candidates.Add([PSCustomObject]@{
            FileName     = ''
            Thumbprint   = ''
            Subject      = ''
            Issuer       = ''
            NotAfter     = ''
            IsSelfSigned = ''
            SubjectMatch = $false
            KeyMatch     = $false
            IsError      = $true
            Error        = $_.Exception.Message
        }) | Out-Null
    }

    return $candidates.ToArray()
}

function Get-ExpectedRootTrustState {
    param(
        [Parameter(Mandatory = $true)]$ChainRow
    )

    $localCandidates = @(Find-IssuerCertificateCandidatesFromStores -ChainRow $ChainRow)

    $status = 'FAIL'
    $result = 'Missing locally'
    $details = 'Not present as trusted root in the local Windows certificate stores used for this chain walk.'
    $thumbprint = ''

    if ($localCandidates.Count -gt 0) {
        $status = 'OK'
        $result = 'Trusted locally'
        $details = 'Present in a local trusted certificate store.'
        try { $thumbprint = [string]$localCandidates[0].Thumbprint } catch { }
    }

    return [PSCustomObject]@{
        Status           = $status
        Result           = $result
        Details          = $details
        Thumbprint       = $thumbprint
        LocalCandidates  = $localCandidates
    }
}

function Get-MissingRootLookupDetails {
    param(
        [Parameter(Mandatory = $true)]$ChainRows
    )

    $lines = New-Object System.Collections.Generic.List[string]

    if (-not $ChainRows -or $ChainRows.Count -eq 0) {
        return $lines.ToArray()
    }

    $highest = $null
    try { $highest = @($ChainRows | Sort-Object -Property Level -Descending | Select-Object -First 1)[0] } catch { }

    if ($null -eq $highest) {
        return $lines.ToArray()
    }

    $highestSubject = ''
    $expectedRoot = ''
    $aki = ''
    $aia = ''
    try { $highestSubject = [string]$highest.Subject } catch { }
    try { $expectedRoot = [string]$highest.Issuer } catch { }
    try { $aki = [string]$highest.AuthorityKeyIdentifier } catch { }
    try { $aia = [string]$highest.AuthorityInfoAccess } catch { }

    $lines.Add('Root lookup from highest chain element:') | Out-Null
    $lines.Add("Highest chain element: $highestSubject") | Out-Null
    $lines.Add("Expected issuer/root: $expectedRoot") | Out-Null

    if (-not [string]::IsNullOrWhiteSpace($aki)) {
        $lines.Add("Authority key identifier: $aki") | Out-Null
    }

    $aiaUrls = @(Get-CertificateAiaCaIssuerUrlsFromText -AuthorityInfoAccess $aia)
    if ($aiaUrls.Count -gt 0) {
        $lines.Add('CA Issuers URL(s) from AIA:') | Out-Null
        foreach ($url in $aiaUrls) {
            $lines.Add("  $url") | Out-Null
        }
    }
    else {
        $lines.Add('CA Issuers URL(s) from AIA: none exposed or not parsed') | Out-Null
    }

    $candidates = @(Find-IssuerCertificateCandidatesFromStores -ChainRow $highest)
    if ($candidates.Count -gt 0) {
        $lines.Add('Matching issuer candidate(s) found in local stores:') | Out-Null
        foreach ($candidate in $candidates) {
            $lines.Add("  $($candidate.Store) | $($candidate.Thumbprint) | SubjectMatch=$($candidate.SubjectMatch) | KeyMatch=$($candidate.KeyMatch)") | Out-Null
        }
    }
    else {
        $lines.Add('Matching issuer candidate(s) found in local stores: none') | Out-Null
    }

    $lines.Add('Microsoft TrustedTPM CAB: not downloaded during the chain walk. Use Check TrustedTPM CAB in the EK certificate window when you want to compare the EK issuer chain against the Microsoft package.') | Out-Null

    $trustState = Get-ExpectedRootTrustState -ChainRow $highest
    $lines.Add("Expected root trust state: $($trustState.Result)") | Out-Null
    $lines.Add("Expected root trust detail: $($trustState.Details)") | Out-Null

    return $lines.ToArray()
}

function New-CertificateChainVisualItems {
    param(
        [Parameter(Mandatory = $true)]$ChainRows
    )

    $visualItems = New-Object System.Collections.Generic.List[object]

    if (-not $ChainRows -or $ChainRows.Count -eq 0) {
        return $visualItems.ToArray()
    }

    $firstRow = $ChainRows[0]
    $chainBuilt = $false
    $overallStatus = ''

    try { $chainBuilt = [bool]$firstRow.ChainBuildSucceeded } catch { }
    try { $overallStatus = [string]$firstRow.OverallStatus } catch { }

    $sortedRows = @($ChainRows | Sort-Object -Property Level -Descending)
    $highestRow = $null
    try { $highestRow = $sortedRows[0] } catch { }

    if (-not $chainBuilt) {
        if ($overallStatus -match 'PartialChain') {
            $expectedRoot = 'Trusted root not found'
            if ($null -ne $highestRow) {
                try {
                    if (-not [string]::IsNullOrWhiteSpace([string]$highestRow.Issuer)) {
                        $expectedRoot = Get-CertificateCommonNameFromSubject -Subject ([string]$highestRow.Issuer)
                    }
                }
                catch { }
            }

            $rootTrustState = $null
            if ($null -ne $highestRow) {
                try { $rootTrustState = Get-ExpectedRootTrustState -ChainRow $highestRow } catch { }
            }

            $rootStatus = 'FAIL'
            $rootStatusText = 'Missing trusted root'
            $rootDetails = 'Not present as trusted root in the local Windows certificate stores'
            $rootThumbprint = ''

            if ($null -ne $rootTrustState) {
                $rootStatus = [string]$rootTrustState.Status
                $rootStatusText = [string]$rootTrustState.Result
                $rootDetails = [string]$rootTrustState.Details
                $rootThumbprint = [string]$rootTrustState.Thumbprint
            }

            if ($rootThumbprint.Length -gt 20) {
                $rootThumbprint = $rootThumbprint.Substring(0, 20) + '...'
            }

            $visualItems.Add([PSCustomObject]@{
                Role       = 'Expected root certificate'
                Name       = $expectedRoot
                Thumbprint = $rootThumbprint
                Status     = $rootStatus
                StatusText = $rootStatusText
                Details    = $rootDetails
                Level      = -1
            }) | Out-Null
        }
        elseif (-not [string]::IsNullOrWhiteSpace($overallStatus) -and $overallStatus -ne 'OK') {
            $visualItems.Add([PSCustomObject]@{
                Role       = 'Chain validation'
                Name       = 'Chain validation issue'
                Thumbprint = ''
                Status     = 'FAIL'
                StatusText = 'Chain failed'
                Details    = $overallStatus
                Level      = -1
            }) | Out-Null
        }
    }

    $maxLevel = 0
    try { $maxLevel = [int](($ChainRows | Measure-Object -Property Level -Maximum).Maximum) } catch { }

    foreach ($row in $sortedRows) {
        $role = 'Intermediate certificate'
        try {
            if ([int]$row.Level -eq 0) {
                $role = 'EK certificate'
            }
            elseif ([string]$row.IsSelfSigned -eq 'True') {
                $role = 'Root certificate'
            }
            elseif ([int]$row.Level -eq $maxLevel -and [string]$row.Subject -match 'Root') {
                $role = 'Root certificate'
            }
        }
        catch { }

        $elementStatus = ''
        try { $elementStatus = [string]$row.ElementStatus } catch { }

        $status = 'OK'
        $statusText = 'OK'
        if ($elementStatus -and $elementStatus -ne 'OK') {
            $status = 'FAIL'
            $statusText = 'Certificate issue'
        }

        $thumb = ''
        try { $thumb = [string]$row.Thumbprint } catch { }

        $thumbShort = $thumb
        if ($thumbShort.Length -gt 20) {
            $thumbShort = $thumbShort.Substring(0, 20) + '...'
        }

        $visualItems.Add([PSCustomObject]@{
            Role       = $role
            Name       = Get-CertificateVisualSubjectText -Subject ([string]$row.Subject)
            Thumbprint = $thumbShort
            Status     = $status
            StatusText = $statusText
            Details    = $elementStatus
            Level      = $row.Level
        }) | Out-Null
    }

    return $visualItems.ToArray()
}

function Show-CertificateChainWindow {
    param(
        [Parameter(Mandatory = $true)]$CertificateItem,
        [Parameter(Mandatory = $true)]$AllCertificateItems
    )

    Start-ProgressWindow -Title 'EK certificate chain' -Maximum 3 -Message 'Building certificate chain...'
    Update-ProgressWindow -Message 'Building certificate chain...' -Detail 'Walking the chain and checking local trust stores. This may take a few seconds.' -Step

    $selectedDisplay = Convert-CertificateForDisplay -Certificate $CertificateItem.Certificate -Type $CertificateItem.Type
    $allCerts = @($AllCertificateItems | ForEach-Object { $_.Certificate })
    $chainRows = @(Get-CertificateChainReport -Certificate $CertificateItem.Certificate -AllCertificates $allCerts)

    Update-ProgressWindow -Message 'Building chain visualisation...' -Detail "$($chainRows.Count) chain element(s) found." -Step
    $visualItems = @(New-CertificateChainVisualItems -ChainRows $chainRows)

    Update-ProgressWindow -Message 'Opening chain window...' -Detail 'Preparing the chain diagram and detail grid.' -Step
    Close-ProgressWindow

    $chainForm = New-Object System.Windows.Forms.Form
    $chainForm.Text = 'EK certificate chain'
    $chainForm.ClientSize = New-Object System.Drawing.Size(1240, 760)
    $chainForm.StartPosition = 'CenterParent'
    $chainForm.MinimumSize = New-Object System.Drawing.Size(1060, 620)
    $chainForm.BackColor = [System.Drawing.Color]::White

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    $layout.RowCount = 5
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 86)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 42)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 24)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 34)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 48)) | Out-Null
    $chainForm.Controls.Add($layout)

    $chainSucceeded = $false
    $overallStatus = ''
    if ($chainRows.Count -gt 0) {
        try { $chainSucceeded = [bool]$chainRows[0].ChainBuildSucceeded } catch { }
        try { $overallStatus = [string]$chainRows[0].OverallStatus } catch { }
    }

    $summary = New-Object System.Windows.Forms.Label
    $summary.Dock = 'Fill'
    $summary.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 4)
    $summary.Font = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
    if ($chainSucceeded) {
        $summary.BackColor = [System.Drawing.Color]::Honeydew
        $summary.ForeColor = [System.Drawing.Color]::ForestGreen
    }
    else {
        $summary.BackColor = [System.Drawing.Color]::MistyRose
        $summary.ForeColor = [System.Drawing.Color]::Firebrick
    }
    $summary.Text = "Selected EK certificate: $($selectedDisplay.Thumbprint)`r`nSubject: $($selectedDisplay.Subject)`r`nChain status: $overallStatus"
    $layout.Controls.Add($summary, 0, 0)

    $visualPanel = New-Object System.Windows.Forms.Panel
    $visualPanel.Dock = 'Fill'
    $visualPanel.BackColor = [System.Drawing.Color]::White
    $visualPanel.AutoScroll = $true
    $visualPanel.Tag = $visualItems
    $visualPanel.Add_Paint({
        param($sender, $eventArgs)

        $graphics = $eventArgs.Graphics
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $items = @($sender.Tag)

        if ($items.Count -eq 0) {
            return
        }

        $boxWidth = 300
        $boxHeight = 118
        $gapX = 74
        $paddingX = 32
        $paddingY = 34
        $lineY = $paddingY + [int]($boxHeight / 2)

        $requiredWidth = ($paddingX * 2) + ($items.Count * $boxWidth) + (($items.Count - 1) * $gapX)
        $requiredHeight = ($paddingY * 2) + $boxHeight + 24
        $sender.AutoScrollMinSize = New-Object System.Drawing.Size($requiredWidth, $requiredHeight)

        $scrollX = $sender.AutoScrollPosition.X
        $scrollY = $sender.AutoScrollPosition.Y

        $positions = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $items.Count; $i++) {
            $positions.Add([PSCustomObject]@{
                X = $paddingX + ($i * ($boxWidth + $gapX)) + $scrollX
                Y = $paddingY + $scrollY
            }) | Out-Null
        }

        $arrowPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(110, 110, 110), 2)
        $arrowCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap(5, 5, $true)
        $arrowPen.CustomEndCap = $arrowCap
        $arrowTextBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, 80, 80))
        $arrowFont = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Regular)

        for ($i = 0; $i -lt ($items.Count - 1); $i++) {
            $current = $positions[$i]
            $next = $positions[$i + 1]
            $startX = $current.X + $boxWidth + 8
            $startY = $lineY + $scrollY
            $endX = $next.X - 8
            $endY = $lineY + $scrollY
            $graphics.DrawLine($arrowPen, $startX, $startY, $endX, $endY)
            $graphics.DrawString('signs', $arrowFont, $arrowTextBrush, [single](($startX + $endX) / 2 - 13), [single]($startY - 22))
        }

        $titleFont = New-Object System.Drawing.Font('Segoe UI', 9.5, [System.Drawing.FontStyle]::Bold)
        $bodyFont = New-Object System.Drawing.Font('Segoe UI', 8.5)
        $smallFont = New-Object System.Drawing.Font('Consolas', 7.8)
        $whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
        $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(135, 135, 135), 1)
        $wrapFormat = New-Object System.Drawing.StringFormat
        $wrapFormat.Trimming = [System.Drawing.StringTrimming]::EllipsisWord
        $wrapFormat.FormatFlags = 0
        $oneLineFormat = New-Object System.Drawing.StringFormat
        $oneLineFormat.Trimming = [System.Drawing.StringTrimming]::EllipsisCharacter
        $oneLineFormat.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap

        for ($i = 0; $i -lt $items.Count; $i++) {
            $item = $items[$i]
            $position = $positions[$i]
            $rect = New-Object System.Drawing.Rectangle($position.X, $position.Y, $boxWidth, $boxHeight)

            $fill = [System.Drawing.Color]::FromArgb(51, 60, 130)
            $textBrush = $whiteBrush

            if ([string]$item.Status -eq 'FAIL') {
                $fill = [System.Drawing.Color]::FromArgb(190, 55, 55)
            }
            elseif ([string]$item.Status -eq 'WARN') {
                $fill = [System.Drawing.Color]::FromArgb(230, 145, 35)
            }
            elseif ([string]$item.Role -eq 'Intermediate certificate') {
                $fill = [System.Drawing.Color]::FromArgb(238, 120, 35)
            }
            elseif ([string]$item.Role -eq 'EK certificate') {
                $fill = [System.Drawing.Color]::FromArgb(82, 160, 72)
            }

            $path = New-RoundedRectanglePath -Rectangle $rect -Radius 15
            $fillBrush = New-Object System.Drawing.SolidBrush($fill)
            $graphics.FillPath($fillBrush, $path)
            $graphics.DrawPath($borderPen, $path)

            $titleRect = New-Object System.Drawing.RectangleF([single]($rect.X + 14), [single]($rect.Y + 10), [single]($rect.Width - 58), [single]22)
            $nameRect = New-Object System.Drawing.RectangleF([single]($rect.X + 14), [single]($rect.Y + 36), [single]($rect.Width - 28), [single]42)
            $thumbRect = New-Object System.Drawing.RectangleF([single]($rect.X + 14), [single]($rect.Y + 82), [single]($rect.Width - 28), [single]18)
            $detailRect = New-Object System.Drawing.RectangleF([single]($rect.X + 14), [single]($rect.Y + 78), [single]($rect.Width - 28), [single]38)

            $graphics.DrawString([string]$item.Role, $titleFont, $textBrush, $titleRect, $oneLineFormat)
            $graphics.DrawString([string]$item.Name, $bodyFont, $textBrush, $nameRect, $wrapFormat)

            $thumb = [string]$item.Thumbprint
            if (-not [string]::IsNullOrWhiteSpace($thumb)) {
                $graphics.DrawString($thumb, $smallFont, $textBrush, $thumbRect, $oneLineFormat)
            }
            else {
                $graphics.DrawString([string]$item.Details, $bodyFont, $textBrush, $detailRect, $wrapFormat)
            }

            if ([string]$item.Status -eq 'FAIL') {
                $crossRect = New-Object System.Drawing.Rectangle(($rect.Right - 35), ($rect.Y + 10), 22, 22)
                $circleBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
                $crossPen = New-Object System.Drawing.Pen([System.Drawing.Color]::Firebrick, 3)
                $graphics.FillEllipse($circleBrush, $crossRect)
                $graphics.DrawLine($crossPen, ($crossRect.X + 6), ($crossRect.Y + 6), ($crossRect.Right - 6), ($crossRect.Bottom - 6))
                $graphics.DrawLine($crossPen, ($crossRect.Right - 6), ($crossRect.Y + 6), ($crossRect.X + 6), ($crossRect.Bottom - 6))
                $circleBrush.Dispose()
                $crossPen.Dispose()
            }
            elseif ([string]$item.Status -eq 'OK') {
                $checkPen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3)
                $graphics.DrawLine($checkPen, ($rect.Right - 33), ($rect.Y + 23), ($rect.Right - 26), ($rect.Y + 30))
                $graphics.DrawLine($checkPen, ($rect.Right - 26), ($rect.Y + 30), ($rect.Right - 14), ($rect.Y + 15))
                $checkPen.Dispose()
            }

            $fillBrush.Dispose()
            $path.Dispose()
        }

        $arrowPen.Dispose()
        $arrowCap.Dispose()
        $arrowTextBrush.Dispose()
        $arrowFont.Dispose()
        $titleFont.Dispose()
        $bodyFont.Dispose()
        $smallFont.Dispose()
        $whiteBrush.Dispose()
        $borderPen.Dispose()
        $wrapFormat.Dispose()
        $oneLineFormat.Dispose()
    })
    $layout.Controls.Add($visualPanel, 0, 1)

    $chainGrid = New-Object System.Windows.Forms.DataGridView
    $chainGrid.Dock = 'Fill'
    $chainGrid.AllowUserToAddRows = $false
    $chainGrid.AllowUserToDeleteRows = $false
    $chainGrid.ReadOnly = $true
    $chainGrid.SelectionMode = 'FullRowSelect'
    $chainGrid.MultiSelect = $false
    $chainGrid.RowHeadersVisible = $false
    $chainGrid.AutoSizeColumnsMode = 'None'
    $chainGrid.ScrollBars = 'Both'
    $chainGrid.BackgroundColor = [System.Drawing.Color]::White
    $chainGrid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $chainGrid.Columns.Add('Level', 'Level') | Out-Null
    $chainGrid.Columns.Add('Status', 'Element status') | Out-Null
    $chainGrid.Columns.Add('Thumbprint', 'Thumbprint') | Out-Null
    $chainGrid.Columns.Add('Subject', 'Subject') | Out-Null
    $chainGrid.Columns.Add('Issuer', 'Issuer') | Out-Null
    $chainGrid.Columns.Add('NotAfter', 'Not After') | Out-Null
    $chainGrid.Columns['Level'].Width = 60
    $chainGrid.Columns['Status'].Width = 260
    $chainGrid.Columns['Thumbprint'].Width = 300
    $chainGrid.Columns['Subject'].Width = 420
    $chainGrid.Columns['Issuer'].Width = 420
    $chainGrid.Columns['NotAfter'].Width = 140

    foreach ($row in $chainRows) {
        $index = $chainGrid.Rows.Add($row.Level, $row.ElementStatus, $row.Thumbprint, $row.Subject, $row.Issuer, $row.NotAfter)
        if ([string]$row.ElementStatus -eq 'OK') {
            $chainGrid.Rows[$index].DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
        }
        else {
            $chainGrid.Rows[$index].DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
        }
    }

    $layout.Controls.Add($chainGrid, 0, 2)

    $detailsBox = New-Object System.Windows.Forms.RichTextBox
    $detailsBox.Dock = 'Fill'
    $detailsBox.ReadOnly = $true
    $detailsBox.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $detailsBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $rootLookupLines = @(Get-MissingRootLookupDetails -ChainRows $chainRows)
    $detailsBox.Text = @(
        "Chain build succeeded: $chainSucceeded"
        "Overall chain status: $overallStatus"
        ''
        'How to read this:'
        'The drawing is shown from the highest chain element on the left to the EK certificate on the right.'
        'A red cross means Windows found a problem for that chain step.'
        'PartialChain usually means the EK certificate and intermediate can be linked, but the trusted root is missing from the local trusted root store or not available to this chain build.'
        'The chain walk checks the local Windows certificate stores and can optionally download issuer certificates from AIA. The TrustedTPM CAB check is separate.'
        ''
        ($rootLookupLines -join [Environment]::NewLine)
        ''
        'Selected certificate details:'
        "Type: $($selectedDisplay.Type)"
        "Thumbprint: $($selectedDisplay.Thumbprint)"
        "Subject: $($selectedDisplay.Subject)"
        "Issuer: $($selectedDisplay.Issuer)"
        "Serial number: $($selectedDisplay.SerialNumber)"
        "Valid from: $($selectedDisplay.NotBefore)"
        "Valid until: $($selectedDisplay.NotAfter)"
        "Signature algorithm: $($selectedDisplay.SignatureAlgorithm)"
        "Public key algorithm: $($selectedDisplay.PublicKeyAlgorithm)"
        "Key size: $($selectedDisplay.KeySize)"
        "Version: $($selectedDisplay.Version)"
        "Self signed: $($selectedDisplay.IsSelfSigned)"
        ''
        'Extensions:'
        "Basic constraints: $($selectedDisplay.BasicConstraints)"
        "Key usage: $($selectedDisplay.KeyUsage)"
        "Enhanced key usage: $($selectedDisplay.EnhancedKeyUsage)"
        "Subject key identifier: $($selectedDisplay.SubjectKeyIdentifier)"
        "Authority key identifier: $($selectedDisplay.AuthorityKeyIdentifier)"
        "Authority information access: $($selectedDisplay.AuthorityInfoAccess)"
    ) -join [Environment]::NewLine
    $layout.Controls.Add($detailsBox, 0, 3)

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.Dock = 'Fill'
    $buttonPanel.FlowDirection = 'RightToLeft'
    $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)
    $layout.Controls.Add($buttonPanel, 0, 4)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Width = 90
    $closeButton.Height = 28
    $buttonPanel.Controls.Add($closeButton)
    $closeButton.Add_Click({ $chainForm.Close() })

    $installCaButton = New-Object System.Windows.Forms.Button
    $installCaButton.Text = 'Download & install missing CA certs'
    $installCaButton.Width = 230
    $installCaButton.Height = 28
    $buttonPanel.Controls.Add($installCaButton)
    $installCaButton.Add_Click({
        try {
            # Collect all certs we already have from the chain to seed the walk
            $seedCerts = New-Object System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]
            try { $seedCerts.Add($CertificateItem.Certificate) | Out-Null } catch { }
            foreach ($item in @($AllCertificateItems)) {
                try { if ($item.Certificate) { $seedCerts.Add($item.Certificate) | Out-Null } } catch { }
            }

            Start-ProgressWindow -Title 'Download & install missing CA certs' -Maximum 6 -Message 'Following AIA chain...'
            Update-ProgressWindow -Message 'Walking issuer chain via AIA...' -Detail "Starting from $($seedCerts.Count) known certificate(s)." -Step

            $result = Invoke-DownloadAndInstallMissingCACerts -StartingCertificates $seedCerts.ToArray()

            Close-ProgressWindow

            # Build summary
            $lines = New-Object System.Collections.Generic.List[string]
            if ($result.Installed.Count -gt 0) {
                $lines.Add("Installed $($result.Installed.Count) certificate(s):") | Out-Null
                foreach ($i in $result.Installed) {
                    $lines.Add("  [$($i.Store)]") | Out-Null
                    $lines.Add("  Subject    : $($i.Subject)") | Out-Null
                    $lines.Add("  Thumbprint : $($i.Thumbprint)") | Out-Null
                    $lines.Add("  Source     : $($i.SourceUrl)") | Out-Null
                    $lines.Add('') | Out-Null
                }
            }
            else {
                $lines.Add('No new certificates were installed.') | Out-Null
                $lines.Add('') | Out-Null
                $lines.Add('This usually means:') | Out-Null
                $lines.Add('- The certificates are already in the local stores, OR') | Out-Null
                $lines.Add('- The AIA extensions on the EK/intermediate certificates do not expose a CA Issuers URL for the root.') | Out-Null
                $lines.Add('') | Out-Null
                $lines.Add('If PartialChain persists, use "Find root in TrustedTPM CAB" to locate and install the root from the Microsoft package instead.') | Out-Null
            }

            if ($result.Failed.Count -gt 0) {
                $lines.Add("$($result.Failed.Count) failure(s):") | Out-Null
                foreach ($f in $result.Failed) { $lines.Add("  $f") | Out-Null }
            }

            if ($result.Installed.Count -gt 0) {
                $lines.Add('Close and reopen the chain window to see the updated chain build result.') | Out-Null
            }

            $icon = if ($result.Installed.Count -gt 0) { 'Information' } else { 'Warning' }
            [System.Windows.Forms.MessageBox]::Show(
                ($lines -join [Environment]::NewLine),
                'Download & install CA certs',
                'OK',
                $icon
            ) | Out-Null

            Update-FinalSummary
        }
        catch {
            Close-ProgressWindow
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Download & install failed', 'OK', 'Error') | Out-Null
        }
    })

    $findRootButton = New-Object System.Windows.Forms.Button
    $findRootButton.Text = 'Find root in TrustedTPM CAB'
    $findRootButton.Width = 205
    $findRootButton.Height = 28
    $buttonPanel.Controls.Add($findRootButton)
    $findRootButton.Add_Click({
        try {
            # Get the highest chain element to find what root we expect
            $highest = $null
            try { $highest = @($chainRows | Sort-Object -Property Level -Descending | Select-Object -First 1)[0] } catch { }

            if (-not $highest) {
                [System.Windows.Forms.MessageBox]::Show('No chain elements available to derive the expected root from.', 'Find root', 'OK', 'Information') | Out-Null
                return
            }

            $expectedIssuer = ''
            $expectedAki    = ''
            try { $expectedIssuer = [string]$highest.Issuer } catch { }
            try { $expectedAki    = [string]$highest.AuthorityKeyIdentifier } catch { }

            if ([string]::IsNullOrWhiteSpace($expectedIssuer) -and [string]::IsNullOrWhiteSpace($expectedAki)) {
                [System.Windows.Forms.MessageBox]::Show('Could not determine the expected root subject or AKI from the highest chain element.', 'Find root', 'OK', 'Warning') | Out-Null
                return
            }

            Start-ProgressWindow -Title 'Finding root in TrustedTPM CAB' -Maximum 4 -Message 'Downloading TrustedTPM CAB...'
            Update-ProgressWindow -Message 'Downloading TrustedTPM CAB...' -Detail 'Using the cached package if already downloaded this session.' -Step

            $package = Get-CachedMicrosoftTpmCaiPackage

            Update-ProgressWindow -Message 'Searching for root certificate...' -Detail "Looking for issuer: $expectedIssuer" -Step

            # Normalise the AKI KeyID for comparison - strip spaces, colons, dashes, lowercase
            $normaliseKeyId = {
                param([string]$raw)
                if ([string]::IsNullOrWhiteSpace($raw)) { return '' }
                return ($raw.ToLowerInvariant() -replace '[^a-f0-9]', '')
            }

            $expectedAkiNorm = & $normaliseKeyId $expectedAki

            $matches = New-Object System.Collections.Generic.List[object]

            foreach ($item in @($package.CertificateItems)) {
                try {
                    $cert = $item.Certificate
                    if (-not $cert) { continue }

                    $subject = [string]$cert.Subject
                    $ski     = ''
                    try {
                        foreach ($ext in $cert.Extensions) {
                            if ($ext.Oid.Value -eq '2.5.29.14') {
                                $ski = (($ext.Format($false)) -replace '[^a-fA-F0-9]', '').ToLowerInvariant()
                                break
                            }
                        }
                    } catch { }

                    $subjectMatch = (-not [string]::IsNullOrWhiteSpace($expectedIssuer)) -and ($subject -eq $expectedIssuer)
                    $skiMatch     = (-not [string]::IsNullOrWhiteSpace($expectedAkiNorm)) -and (-not [string]::IsNullOrWhiteSpace($ski)) -and ($ski -eq $expectedAkiNorm)

                    if ($subjectMatch -or $skiMatch) {
                        $matches.Add([PSCustomObject]@{
                            FileName      = $item.FileName
                            Thumbprint    = $cert.Thumbprint
                            Subject       = $subject
                            Issuer        = [string]$cert.Issuer
                            NotAfter      = [string]$cert.NotAfter
                            IsSelfSigned  = ($cert.Subject -eq $cert.Issuer)
                            SubjectMatch  = $subjectMatch
                            SkiMatch      = $skiMatch
                            Certificate   = $cert
                        }) | Out-Null
                    }
                }
                catch { }
            }

            Update-ProgressWindow -Message 'Done.' -Detail "$($matches.Count) candidate(s) found." -Step
            Close-ProgressWindow

            if ($matches.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show(
                    "No certificate matching the expected root was found in the TrustedTPM CAB.`n`nExpected issuer: $expectedIssuer`nExpected AKI: $expectedAki",
                    'Root not found in TrustedTPM CAB', 'OK', 'Warning') | Out-Null
                return
            }

            # Build result message
            $lines = New-Object System.Collections.Generic.List[string]
            $lines.Add("Found $($matches.Count) candidate root certificate(s) in the TrustedTPM CAB matching:") | Out-Null
            $lines.Add("  Expected issuer : $expectedIssuer") | Out-Null
            $lines.Add("  Expected AKI    : $expectedAki") | Out-Null
            $lines.Add('') | Out-Null

            foreach ($m in $matches) {
                $lines.Add("CAB file   : $($m.FileName)") | Out-Null
                $lines.Add("Thumbprint : $($m.Thumbprint)") | Out-Null
                $lines.Add("Subject    : $($m.Subject)") | Out-Null
                $lines.Add("Issuer     : $($m.Issuer)") | Out-Null
                $lines.Add("Self-signed: $($m.IsSelfSigned)") | Out-Null
                $lines.Add("Valid until: $($m.NotAfter)") | Out-Null
                $lines.Add("Match on   : $(if ($m.SubjectMatch -and $m.SkiMatch) { 'Subject + SKI' } elseif ($m.SubjectMatch) { 'Subject' } else { 'SKI' })") | Out-Null
                $lines.Add('') | Out-Null
            }

            $lines.Add('This root is expected to be trusted via the TrustedTPM CAB package, not the local Windows root store.') | Out-Null
            $lines.Add('PartialChain during the local chain walk is normal for EK certificates - the AIK test result is the authoritative indicator.') | Out-Null
            $lines.Add('') | Out-Null
            $lines.Add('You can optionally install the root into the local machine Trusted Root store to make the chain walk succeed. This is informational only and not required for Autopilot attestation.') | Out-Null

            $resultMsg = $lines -join [Environment]::NewLine

            $answer = [System.Windows.Forms.MessageBox]::Show(
                $resultMsg,
                'Root certificate found in TrustedTPM CAB',
                'YesNo',
                'Information'
            )

            # YesNo here is reused - re-prompt clearly
            $install = [System.Windows.Forms.MessageBox]::Show(
                "Install the root certificate into the local machine Trusted Root store?`n`nThis makes the chain walk succeed and is harmless - the cert is already trusted by Windows via the TrustedTPM CAB.`nRequires elevation.",
                'Install root certificate?',
                'YesNo',
                'Question'
            )

            if ($install -eq [System.Windows.Forms.DialogResult]::Yes) {
                $installed = 0
                $errors    = New-Object System.Collections.Generic.List[string]

                foreach ($m in $matches) {
                    try {
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
                            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
                        )
                        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                        $store.Add($m.Certificate)
                        $store.Close()
                        $installed++
                        Add-Result -Category 'EK Chain' -Check 'Root certificate installed' -Status 'PASS' -Details "Installed $($m.Thumbprint) ($($m.Subject)) from TrustedTPM CAB file $($m.FileName) into LocalMachine\Root."
                    }
                    catch {
                        $errors.Add("$($m.Thumbprint): $($_.Exception.Message)") | Out-Null
                        Add-Result -Category 'EK Chain' -Check 'Root certificate install failed' -Status 'FAIL' -Details "$($m.Thumbprint): $($_.Exception.Message)" -Remediation 'Run the tool as administrator to install into LocalMachine\Root.'
                    }
                }

                if ($installed -gt 0) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "$installed root certificate(s) installed into LocalMachine\Root.`n`nClose and reopen the chain window to see the updated chain build result.",
                        'Root certificate installed', 'OK', 'Information') | Out-Null
                }
                if ($errors.Count -gt 0) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to install $($errors.Count) certificate(s):`n`n$($errors -join [Environment]::NewLine)",
                        'Install failed', 'OK', 'Error') | Out-Null
                }
            }
        }
        catch {
            Close-ProgressWindow
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Find root failed', 'OK', 'Error') | Out-Null
        }
    })

    $aiaButton = New-Object System.Windows.Forms.Button
    $aiaButton.Text = 'Fetch issuer from AIA'
    $aiaButton.Width = 155
    $aiaButton.Height = 28
    $buttonPanel.Controls.Add($aiaButton)
    $aiaButton.Add_Click({
        try {
            $downloadedItems = @(Get-AiaIssuerCertificateItemsFromChainRows -ChainRows $chainRows)
            $downloadFailures = @($downloadedItems | Where-Object { $_.Certificate -eq $null })
            $validDownloadedItems = @($downloadedItems | Where-Object { $_.Certificate -ne $null })

            if ($validDownloadedItems.Count -eq 0) {
                $message = 'No issuer certificate could be downloaded from the CA Issuers AIA URLs in the current chain.'
                if ($downloadFailures.Count -gt 0) {
                    $message += [Environment]::NewLine + [Environment]::NewLine + (($downloadFailures | ForEach-Object { "$($_.SourceUrl): $($_.Error)" }) -join [Environment]::NewLine)
                }
                [System.Windows.Forms.MessageBox]::Show($message, 'AIA issuer download', 'OK', 'Information') | Out-Null
                return
            }

            $combinedItems = @(Get-UniqueCertificateItems -CertificateItems (@($AllCertificateItems) + $validDownloadedItems))
            Add-Result -Category 'EK Chain' -Check 'AIA issuer download' -Status 'INFO' -Result "Downloaded=$($validDownloadedItems.Count)" -Details "Downloaded issuer certificate(s) from AIA URL(s): $((@($validDownloadedItems | ForEach-Object { $_.SourceUrl }) | Select-Object -Unique) -join '; ')"
            Show-CertificateChainWindow -CertificateItem $CertificateItem -AllCertificateItems $combinedItems
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'AIA issuer download failed', 'OK', 'Error') | Out-Null
        }
    })


    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = 'Copy'
    $copyButton.Width = 90
    $copyButton.Height = 28
    $buttonPanel.Controls.Add($copyButton)
    $copyButton.Add_Click({
        $text = @(
            $detailsBox.Text
            ''
            'Root lookup:'
            ($rootLookupLines -join [Environment]::NewLine)
            ''
            'Visual chain steps:'
            ($visualItems | Format-Table Role, Name, Status, Thumbprint, Details -AutoSize | Out-String).Trim()
            ''
            'Chain elements:'
            ($chainRows | Format-Table Level, ElementStatus, Thumbprint, Subject, Issuer -AutoSize | Out-String).Trim()
        ) -join [Environment]::NewLine
        [System.Windows.Forms.Clipboard]::SetText($text)
    })

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = 'Export chain CSV'
    $exportButton.Width = 130
    $exportButton.Height = 28
    $buttonPanel.Controls.Add($exportButton)
    $exportButton.Add_Click({
        try {
            $folder = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
            if (-not (Test-Path $folder)) {
                New-Item -Path $folder -ItemType Directory -Force | Out-Null
            }

            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $path = Join-Path $folder "TPM_Endorsement_Certificate_Chain_$stamp.csv"
            $chainRows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Start-Process explorer.exe -ArgumentList "/select,`"$path`""
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error') | Out-Null
        }
    })

    [void]$chainForm.ShowDialog()
}

function Show-TpmEndorsementCertificates {
    Start-ProgressWindow -Title 'Reading EK certificates' -Maximum 3 -Message 'Reading TPM endorsement certificates...'

    try {
        Update-ProgressWindow -Message 'Querying Get-TpmEndorsementKeyInfo' -Detail 'Reading ManufacturerCertificates and AdditionalCertificates.' -Step
        $certificateObjects = @(Get-TpmEndorsementCertificateObjects -AddToResults)
        $certs = New-Object System.Collections.Generic.List[object]

        Update-ProgressWindow -Message 'Reading certificate properties' -Detail 'Parsing certificate metadata and extensions.' -Step
        foreach ($item in $certificateObjects) {
            try {
                $certs.Add((Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type)) | Out-Null
            }
            catch { }
        }

        Update-ProgressWindow -Message 'Building certificate window...' -Detail "$($certs.Count) certificate(s) found." -Step
        Close-ProgressWindow

        if ($certs.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No ManufacturerCertificates or AdditionalCertificates were returned by Get-TpmEndorsementKeyInfo.', 'No EK certificates found', 'OK', 'Warning') | Out-Null
            return
        }

        $certForm = New-Object System.Windows.Forms.Form
        $certForm.Text = 'TPM endorsement certificates'
        $certForm.ClientSize = New-Object System.Drawing.Size(1200, 560)
        $certForm.StartPosition = 'CenterParent'
        $certForm.MinimumSize = New-Object System.Drawing.Size(980, 420)
        $certForm.BackColor = [System.Drawing.Color]::White

        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 3
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 64)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 48)) | Out-Null
        $certForm.Controls.Add($layout)

        $label = New-Object System.Windows.Forms.Label
        $label.Dock = 'Fill'
        $label.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 4)
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $label.Text = "Get-TpmEndorsementKeyInfo returned $($certs.Count) endorsement certificate(s). Select a certificate, walk the chain, fetch issuer certificates from AIA, refresh the EK certificate from NV/Web, or validate the EK issuer chain against the Microsoft TrustedTPM CAB."
        $layout.Controls.Add($label, 0, 0)

        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.ReadOnly = $true
        $grid.SelectionMode = 'FullRowSelect'
        $grid.MultiSelect = $false
        $grid.RowHeadersVisible = $false
        $grid.AutoSizeColumnsMode = 'None'
        $grid.ScrollBars = 'Both'
        $grid.BackgroundColor = [System.Drawing.Color]::White
        $grid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $grid.Columns.Add('Type', 'Type') | Out-Null
        $grid.Columns.Add('Thumbprint', 'Thumbprint') | Out-Null
        $grid.Columns.Add('Subject', 'Subject') | Out-Null
        $grid.Columns.Add('Issuer', 'Issuer') | Out-Null
        $grid.Columns.Add('SerialNumber', 'Serial Number') | Out-Null
        $grid.Columns.Add('NotBefore', 'Not Before') | Out-Null
        $grid.Columns.Add('NotAfter', 'Not After') | Out-Null
        $grid.Columns.Add('SignatureAlgorithm', 'Signature Algorithm') | Out-Null
        $grid.Columns.Add('PublicKeyAlgorithm', 'Public Key') | Out-Null
        $grid.Columns.Add('KeySize', 'Key Size') | Out-Null
        $grid.Columns.Add('EnhancedKeyUsage', 'Enhanced Key Usage') | Out-Null
        $grid.Columns.Add('BasicConstraints', 'Basic Constraints') | Out-Null
        $grid.Columns['Type'].Width = 110
        $grid.Columns['Thumbprint'].Width = 300
        $grid.Columns['Subject'].Width = 460
        $grid.Columns['Issuer'].Width = 460
        $grid.Columns['SerialNumber'].Width = 220
        $grid.Columns['NotBefore'].Width = 140
        $grid.Columns['NotAfter'].Width = 140
        $grid.Columns['SignatureAlgorithm'].Width = 180
        $grid.Columns['PublicKeyAlgorithm'].Width = 140
        $grid.Columns['KeySize'].Width = 90
        $grid.Columns['EnhancedKeyUsage'].Width = 320
        $grid.Columns['BasicConstraints'].Width = 260

        foreach ($cert in $certs) {
            $grid.Rows.Add(
                $cert.Type,
                $cert.Thumbprint,
                $cert.Subject,
                $cert.Issuer,
                $cert.SerialNumber,
                $cert.NotBefore,
                $cert.NotAfter,
                $cert.SignatureAlgorithm,
                $cert.PublicKeyAlgorithm,
                $cert.KeySize,
                $cert.EnhancedKeyUsage,
                $cert.BasicConstraints
            ) | Out-Null
        }

        if ($grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
        }

        $layout.Controls.Add($grid, 0, 1)

        $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $buttonPanel.Dock = 'Fill'
        $buttonPanel.FlowDirection = 'RightToLeft'
        $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 8)
        $layout.Controls.Add($buttonPanel, 0, 2)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = 'Close'
        $closeButton.Width = 90
        $closeButton.Height = 28
        $buttonPanel.Controls.Add($closeButton)
        $closeButton.Add_Click({ $certForm.Close() })

        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Text = 'Copy'
        $copyButton.Width = 90
        $copyButton.Height = 28
        $buttonPanel.Controls.Add($copyButton)
        $copyButton.Add_Click({
            $text = ($certs | Format-Table Type, Thumbprint, Subject, Issuer, NotAfter, SignatureAlgorithm, PublicKeyAlgorithm, KeySize -AutoSize | Out-String).Trim()
            [System.Windows.Forms.Clipboard]::SetText($text)
        })

        $exportButton = New-Object System.Windows.Forms.Button
        $exportButton.Text = 'Export CSV'
        $exportButton.Width = 100
        $exportButton.Height = 28
        $buttonPanel.Controls.Add($exportButton)
        $exportButton.Add_Click({
            try {
                $folder = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
                if (-not (Test-Path $folder)) {
                    New-Item -Path $folder -ItemType Directory -Force | Out-Null
                }

                $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $path = Join-Path $folder "TPM_Endorsement_Certificates_$stamp.csv"
                $certs | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
                Start-Process explorer.exe -ArgumentList "/select,`"$path`""
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error') | Out-Null
            }
        })

        $chainButton = New-Object System.Windows.Forms.Button
        $chainButton.Text = 'Walk chain'
        $chainButton.Width = 105
        $chainButton.Height = 28
        $buttonPanel.Controls.Add($chainButton)
        $chainButton.Add_Click({
            try {
                if ($grid.SelectedRows.Count -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show('Select a certificate first.', 'No certificate selected', 'OK', 'Information') | Out-Null
                    return
                }

                $selectedIndex = $grid.SelectedRows[0].Index
                if ($selectedIndex -lt 0 -or $selectedIndex -ge $certificateObjects.Count) {
                    [System.Windows.Forms.MessageBox]::Show('The selected certificate could not be mapped back to the certificate object.', 'Certificate mapping failed', 'OK', 'Warning') | Out-Null
                    return
                }

                Show-CertificateChainWindow -CertificateItem $certificateObjects[$selectedIndex] -AllCertificateItems $certificateObjects
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Chain walk failed', 'OK', 'Error') | Out-Null
            }
        })

        $refreshEkButton = New-Object System.Windows.Forms.Button
        $refreshEkButton.Text = 'Refresh EK from NV/Web'
        $refreshEkButton.Width = 165
        $refreshEkButton.Height = 28
        $buttonPanel.Controls.Add($refreshEkButton)
        $refreshEkButton.Add_Click({
            try {
                $answer = [System.Windows.Forms.MessageBox]::Show('This will run the local TPM EK certificate retrieval actions: TpmCertInstallNvEkCerts, TpmCertGetEkCertFromWeb, and TpmRetrieveEkCertOrReschedule. It does not clear the TPM. Continue?', 'Refresh EK certificate', 'YesNo', 'Question')
                if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }

                Start-ProgressWindow -Title 'Refresh EK certificate' -Maximum 3 -Message 'Trying EK certificate retrieval actions...'
                $dll = Resolve-LocalOrInboxFile -FileName 'TpmCoreProvisioning.dll' -InboxPath (Join-Path $env:WINDIR 'System32\tpmcoreprovisioning.dll')
                $functions = @('TpmCertInstallNvEkCerts', 'TpmCertGetEkCertFromWeb', 'TpmRetrieveEkCertOrReschedule')
                foreach ($functionName in $functions) {
                    Update-ProgressWindow -Message "Running $functionName" -Detail "Using $dll" -Step
                    Invoke-TpmCoreProvisioningFunction -FunctionName $functionName
                }
                Close-ProgressWindow
                [System.Windows.Forms.MessageBox]::Show('EK retrieval actions were started. Close and reopen the EK certificate window to reload Get-TpmEndorsementKeyInfo.', 'Refresh EK certificate', 'OK', 'Information') | Out-Null
            }
            catch {
                Close-ProgressWindow
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Refresh EK certificate failed', 'OK', 'Error') | Out-Null
            }
        })


        $caiButton = New-Object System.Windows.Forms.Button
        $caiButton.Text = 'Check TrustedTPM CAB'
        $caiButton.Width = 145
        $caiButton.Height = 28
        $buttonPanel.Controls.Add($caiButton)
        $caiButton.Add_Click({
            try {
                Test-EkCertificatesAgainstMicrosoftCai -CertificateItems $certificateObjects
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'TrustedTPM CAB check failed', 'OK', 'Error') | Out-Null
            }
        })

        [void]$certForm.ShowDialog()
    }
    finally {
        Close-ProgressWindow
    }
}


function Show-TpmEndorsementCertificateChainPicker {
    try {
        Start-ProgressWindow -Title 'EK certificate chain' -Maximum 3 -Message 'Preparing EK certificate chain...'
        Update-ProgressWindow -Message 'Reading EK certificates' -Detail 'Calling Get-TpmEndorsementKeyInfo.' -Step

        $certificateObjects = @(Get-TpmEndorsementCertificateObjects -AddToResults)

        Update-ProgressWindow -Message 'Preparing chain picker' -Detail "$($certificateObjects.Count) certificate object(s) found." -Step
        Close-ProgressWindow

        if ($certificateObjects.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No ManufacturerCertificates or AdditionalCertificates were returned by Get-TpmEndorsementKeyInfo.', 'No EK certificates found', 'OK', 'Warning') | Out-Null
            return
        }

        if ($certificateObjects.Count -eq 1) {
            Show-CertificateChainWindow -CertificateItem $certificateObjects[0] -AllCertificateItems $certificateObjects
            return
        }

        $pickerForm = New-Object System.Windows.Forms.Form
        $pickerForm.Text = 'Walk EK certificate chain'
        $pickerForm.ClientSize = New-Object System.Drawing.Size(1120, 520)
        $pickerForm.StartPosition = 'CenterParent'
        $pickerForm.MinimumSize = New-Object System.Drawing.Size(900, 420)
        $pickerForm.BackColor = [System.Drawing.Color]::White

        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = 'Fill'
        $layout.ColumnCount = 1
        $layout.RowCount = 3
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 58)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 48)) | Out-Null
        $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
        $pickerForm.Controls.Add($layout)

        $label = New-Object System.Windows.Forms.Label
        $label.Dock = 'Fill'
        $label.Padding = New-Object System.Windows.Forms.Padding(14, 8, 14, 4)
        $label.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $label.Text = "Select the EK certificate you want to chain walk. Windows will build the chain using the returned ManufacturerCertificates and AdditionalCertificates as extra store input."
        $layout.Controls.Add($label, 0, 0)

        $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $buttonPanel.Dock = 'Fill'
        $buttonPanel.FlowDirection = 'LeftToRight'
        $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
        $buttonPanel.BackColor = [System.Drawing.Color]::White
        $layout.Controls.Add($buttonPanel, 0, 1)

        $walkButton = New-Object System.Windows.Forms.Button
        $walkButton.Text = 'Walk selected chain'
        $walkButton.Width = 150
        $walkButton.Height = 28
        $buttonPanel.Controls.Add($walkButton)

        $openCertsButton = New-Object System.Windows.Forms.Button
        $openCertsButton.Text = 'Show cert details'
        $openCertsButton.Width = 130
        $openCertsButton.Height = 28
        $buttonPanel.Controls.Add($openCertsButton)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = 'Close'
        $closeButton.Width = 90
        $closeButton.Height = 28
        $buttonPanel.Controls.Add($closeButton)
        $closeButton.Add_Click({ $pickerForm.Close() })

        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'
        $grid.AllowUserToAddRows = $false
        $grid.AllowUserToDeleteRows = $false
        $grid.ReadOnly = $true
        $grid.SelectionMode = 'FullRowSelect'
        $grid.MultiSelect = $false
        $grid.RowHeadersVisible = $false
        $grid.AutoSizeColumnsMode = 'None'
        $grid.ScrollBars = 'Both'
        $grid.BackgroundColor = [System.Drawing.Color]::White
        $grid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $grid.Columns.Add('Type', 'Type') | Out-Null
        $grid.Columns.Add('Thumbprint', 'Thumbprint') | Out-Null
        $grid.Columns.Add('Subject', 'Subject') | Out-Null
        $grid.Columns.Add('Issuer', 'Issuer') | Out-Null
        $grid.Columns.Add('NotAfter', 'Not After') | Out-Null
        $grid.Columns['Type'].Width = 120
        $grid.Columns['Thumbprint'].Width = 300
        $grid.Columns['Subject'].Width = 420
        $grid.Columns['Issuer'].Width = 420
        $grid.Columns['NotAfter'].Width = 150

        foreach ($item in $certificateObjects) {
            try {
                $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type
                $grid.Rows.Add($display.Type, $display.Thumbprint, $display.Subject, $display.Issuer, $display.NotAfter) | Out-Null
            }
            catch { }
        }

        if ($grid.Rows.Count -gt 0) {
            $grid.Rows[0].Selected = $true
        }

        $layout.Controls.Add($grid, 0, 2)

        $walkButton.Add_Click({
            try {
                if ($grid.SelectedRows.Count -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show('Select a certificate first.', 'No certificate selected', 'OK', 'Information') | Out-Null
                    return
                }

                $selectedIndex = $grid.SelectedRows[0].Index
                if ($selectedIndex -lt 0 -or $selectedIndex -ge $certificateObjects.Count) {
                    [System.Windows.Forms.MessageBox]::Show('The selected certificate could not be mapped back to the certificate object.', 'Certificate mapping failed', 'OK', 'Warning') | Out-Null
                    return
                }

                Show-CertificateChainWindow -CertificateItem $certificateObjects[$selectedIndex] -AllCertificateItems $certificateObjects
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Chain walk failed', 'OK', 'Error') | Out-Null
            }
        })

        $openCertsButton.Add_Click({
            try {
                $pickerForm.Close()
                Show-TpmEndorsementCertificates
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Certificate details failed', 'OK', 'Error') | Out-Null
            }
        })

        [void]$pickerForm.ShowDialog()
    }
    finally {
        Close-ProgressWindow
    }
}


function Test-InfineonFirmware {
    function Test-IsInfineonFirmwareVersionAffected {
        param([int[]]$FirmwareVersion)
        $major = $FirmwareVersion[0]
        $minor = $FirmwareVersion[1]

        switch ($major) {
            4   { return ($minor -le 33 -or ($minor -ge 40 -and $minor -le 42)) }
            5   { return ($minor -le 61) }
            6   { return ($minor -le 42) }
            7   { return ($minor -le 61) }
            133 { return ($minor -le 32) }
            default { return $false }
        }
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $ifxManufacturerIdInt = 0x49465800

        if ($tpm.ManufacturerId -ne $ifxManufacturerIdInt) {
            Add-Result -Category 'TPM Firmware' -Check 'Infineon vulnerability check' -Status 'PASS' -Details 'TPM manufacturer is not Infineon.'
            return
        }

        $parts = @($tpm.ManufacturerVersion -split '\.' | ForEach-Object { [int]$_ })
        if ($parts.Count -lt 2) {
            Add-Result -Category 'TPM Firmware' -Check 'Infineon firmware version' -Status 'WARN' -Details "Could not parse version: $($tpm.ManufacturerVersion)"
            return
        }

        if (Test-IsInfineonFirmwareVersionAffected -FirmwareVersion $parts) {
            Add-Result -Category 'TPM Firmware' -Check 'Infineon firmware version' -Status 'FAIL' -Details "Affected firmware version: $($parts[0]).$($parts[1])" -Remediation 'Update TPM firmware and clear the TPM according to vendor guidance.'
        }
        else {
            Add-Result -Category 'TPM Firmware' -Check 'Infineon firmware version' -Status 'PASS' -Details "Safe firmware version: $($parts[0]).$($parts[1])"
        }

        $lastProvision = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI' -Name 'FirmwareVersionAtLastProvision' -ErrorAction SilentlyContinue).FirmwareVersionAtLastProvision
        if (-not $lastProvision) {
            Add-Result -Category 'TPM Firmware' -Check 'Firmware at last provision' -Status 'WARN' -Details 'FirmwareVersionAtLastProvision was not found.' -Remediation 'If firmware was updated recently, clear and provision TPM following your internal process.'
        }
    }
    catch {
        Add-Result -Category 'TPM Firmware' -Check 'Firmware check' -Status 'WARN' -Details $_.Exception.Message
    }
}

function Test-KeyAttestationCapable {
    $tpmCim = Get-TpmCimInstanceSafe

    if (-not $tpmCim) {
        Add-Result -Category 'Attestation' -Check 'Key attestation capable' -Status 'FAIL' -Details 'TPM WMI provider unavailable.'
        return
    }

    try {
        $capable = $tpmCim | Invoke-CimMethod -MethodName IsKeyAttestationCapable -ErrorAction Stop
        $code = [int64]$capable.TestResult

        if ($code -eq 0) {
            Add-Result -Category 'Attestation' -Check 'Key attestation capable' -Status 'PASS' -Details 'IsKeyAttestationCapable returned 0.'
        }
        else {
            Add-Result -Category 'Attestation' -Check 'Key attestation capable' -Status 'FAIL' -Details "IsKeyAttestationCapable returned $code." -Remediation 'Run tpmtool getdeviceinformation and check TPM capability output.'
        }
    }
    catch {
        Add-Result -Category 'Attestation' -Check 'Key attestation capable' -Status 'FAIL' -Details $_.Exception.Message
    }
}

function Test-AikEnrollmentTask {
    try {
        Start-ScheduledTask -TaskPath '\Microsoft\Windows\CertificateServicesClient\' -TaskName 'AikCertEnrollTask' -ErrorAction Stop
        Start-SleepWithDoEvents -Seconds 5

        $aikReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\AIKCertEnroll'
        $errorCode = (Get-ItemProperty -Path $aikReg -Name 'ErrorCode' -ErrorAction SilentlyContinue).ErrorCode

        if ($null -eq $errorCode) {
            Add-Result -Category 'AIK' -Check 'AIKCertEnrollTask' -Status 'WARN' -Details 'Task started, but ErrorCode registry value was not found.' -Remediation 'Check CertificateServicesClient and TPM event logs.'
        }
        elseif ([int64]$errorCode -eq 0) {
            Add-Result -Category 'AIK' -Check 'AIKCertEnrollTask' -Status 'PASS' -Details 'AIK certificate enrollment task completed without registered error.'
        }
        else {
            Add-Result -Category 'AIK' -Check 'AIKCertEnrollTask' -Status 'FAIL' -Details "AIK ErrorCode: $errorCode" -Remediation 'Run tpmtool getdeviceinformation and review AIK enrollment details.'
        }
    }
    catch {
        Add-Result -Category 'AIK' -Check 'AIKCertEnrollTask' -Status 'WARN' -Details $_.Exception.Message -Remediation 'Check if the scheduled task exists on this Windows build.'
    }
}

function Get-UrlsFromText {
    param(
        [AllowNull()][string]$Text
    )

    $urls = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $urls.ToArray() }

    foreach ($match in [regex]::Matches($Text, 'https?://[^\s\"''<>\)\]]+')) {
        $url = $match.Value.Trim().TrimEnd('.', ',', ';', ':')
        if (-not [string]::IsNullOrWhiteSpace($url) -and -not $urls.Contains($url)) {
            $urls.Add($url) | Out-Null
        }
    }

    return $urls.ToArray()
}

function Convert-PemBlockToCertificate {
    param(
        [AllowNull()][string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $match = [regex]::Match($Text, '-----BEGIN CERTIFICATE-----\s*(?<Body>[A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $match.Success) { return $null }

    try {
        $body = ($match.Groups['Body'].Value -replace '\s+', '')
        $bytes = [Convert]::FromBase64String($body)
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$bytes)
    }
    catch {
        Write-AppLog -Message "Could not parse returned test AIK certificate: $($_.Exception.Message)" -Level 'DEBUG'
        return $null
    }
}


function Test-IsAikImpersonationError {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match '0x80070542|BAD_IMPERSONATION_LEVEL|impersonation level')
}

function Invoke-AikCertreqAsSystem {
    # Relaunches certreq -enrollaik as SYSTEM via a one-shot scheduled task so that
    # CertEnroll.dll::EnrollForAIKCertificate gets the impersonation level it requires.
    # Returns a PSCustomObject with: Output (string), ExitCode (int), TempFolder (string to clean up).

    $taskName  = "AutopilotTpmTool_AikTest_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $baseDir   = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
    $taskDir   = Join-Path $baseDir "AikSystemTest_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    $outputFile = Join-Path $taskDir 'certreq_output.txt'
    $scriptFile = Join-Path $taskDir 'run_aik.ps1'
    $exitFile   = Join-Path $taskDir 'exitcode.txt'

    $result = [PSCustomObject]@{
        Output     = ''
        ExitCode   = -1
        TempFolder = $taskDir
        TaskName   = $taskName
        Error      = ''
    }

    try {
        New-Item -Path $taskDir -ItemType Directory -Force | Out-Null

        # The script that runs as SYSTEM: run certreq, capture all output, write exit code
        $scriptContent = @"
`$cmd = Join-Path `$env:WINDIR 'System32\cmd.exe'
`$psi = New-Object System.Diagnostics.ProcessStartInfo
`$psi.FileName = `$cmd
`$psi.Arguments = '/d /c certreq -q -enrollaik -config ""'
`$psi.UseShellExecute = `$false
`$psi.CreateNoWindow = `$true
`$psi.RedirectStandardOutput = `$true
`$psi.RedirectStandardError = `$true
`$p = New-Object System.Diagnostics.Process
`$p.StartInfo = `$psi
[void]`$p.Start()
`$stdout = `$p.StandardOutput.ReadToEnd()
`$stderr = `$p.StandardError.ReadToEnd()
`$p.WaitForExit()
`$combined = `$stdout + [Environment]::NewLine + `$stderr
[System.IO.File]::WriteAllText('$($outputFile -replace "'","''")', `$combined, [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText('$($exitFile -replace "'","''")', `$p.ExitCode.ToString(), [System.Text.Encoding]::UTF8)
"@
        [System.IO.File]::WriteAllText($scriptFile, $scriptContent, [System.Text.Encoding]::UTF8)

        # Register a one-shot scheduled task running as SYSTEM
        $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptFile`""
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew

        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop

        # Wait up to 120 s for the output file to appear, pumping DoEvents so the spinner ticks
        $deadline = (Get-Date).AddSeconds(120)
        $waitSec = 0
        while (-not (Test-Path $outputFile) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 50
            [System.Windows.Forms.Application]::DoEvents()
            $waitSec++
            if ($waitSec % 20 -eq 0) {   # every ~1 second
                $elapsed = [int]($waitSec / 20)
                Update-ProgressWindow -Message "Waiting for certreq SYSTEM task (${elapsed}s elapsed, up to 120s)..." -Detail "Output file: $outputFile"
            }
        }

        # Give it one more tick to finish writing, still pumping
        $settle = (Get-Date).AddSeconds(1)
        while ((Get-Date) -lt $settle) {
            Start-Sleep -Milliseconds 50
            [System.Windows.Forms.Application]::DoEvents()
        }

        if (Test-Path $outputFile) {
            $result.Output = [System.IO.File]::ReadAllText($outputFile, [System.Text.Encoding]::UTF8)
        }
        else {
            $result.Error = 'certreq output file was not created within 120 seconds.'
        }

        if (Test-Path $exitFile) {
            $exitRaw = [System.IO.File]::ReadAllText($exitFile, [System.Text.Encoding]::UTF8).Trim()
            $parsed = 0
            if ([int]::TryParse($exitRaw, [ref]$parsed)) { $result.ExitCode = $parsed }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        # Clean up the scheduled task regardless of outcome
        try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    }

    return $result
}


function Get-TpmReadyInformationCodeSafe {
    try {
        $tpmCim = Get-TpmCimInstanceSafe
        if (-not $tpmCim) { return $null }

        $attestation = $tpmCim | Invoke-CimMethod -MethodName IsReadyInformation -ErrorAction Stop
        return [int64]$attestation.Information
    }
    catch {
        Write-AppLog -Message "Could not read IsReadyInformation before AIK certreq test: $($_.Exception.Message)" -Level 'DEBUG'
        return $null
    }
}

function Test-AikTestCertificate {
    param(
        [string]$Category = 'AIK',
        [string]$CheckName = 'Test AIK certificate',
        [int]$AttemptCount = 10,
        [switch]$ShowPopup,
        [switch]$AllowWhenNotReady
    )

    $lastText = ''
    $lastUrls = @()
    $trustedTpmChecked = $false
    $foundCertificate = $false

    # Ensure the spinner is always visible for this function regardless of caller.
    # If Start-ProgressWindow was already called by the parent (Invoke-AllChecks etc.)
    # this just updates the message; if called standalone it starts the overlay.
    Start-SpinnerOverlay -Message 'AIK certreq test...' -Detail 'Checking if TPM is ready for attestation.'

    try {
        $readyCode = Get-TpmReadyInformationCodeSafe
        if (($null -ne $readyCode) -and ($readyCode -ne 0) -and (-not $AllowWhenNotReady)) {
            Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'Skipped' -Details "Skipping certreq AIK test because IsReadyInformation returned $readyCode. This follows the original script logic: only run certreq -enrollaik when TPM reports ready for attestation." -Remediation 'Fix the TPM ready state first, then rerun the AIK test.'
            if ($ShowPopup) {
                Show-AikTestOutputWindow -Title 'AIK test skipped' -Text "IsReadyInformation returned $readyCode. The AIK certreq test was skipped because the TPM is not ready for attestation yet." -Urls @()
            }
            return
        }

        $certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
        if (-not (Test-Path $certreq)) {
            Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'certreq missing' -Details 'certreq.exe was not found.'
            return
        }

        $cmd = Join-Path $env:WINDIR 'System32\cmd.exe'
        if (-not (Test-Path $cmd)) {
            Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'cmd missing' -Details 'cmd.exe was not found. The AIK test command is meant to run through Command Prompt.'
            return
        }

        try {
            $identityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            if ($identityName -match '^(NT AUTHORITY|AUTORITEIT NT)\\SYSTEM$') {
                Add-Result -Category $Category -Check 'AIK test context' -Status 'WARN' -Result 'SYSTEM context' -Details 'The certreq AIK test is running as SYSTEM. The AIK certreq test is more reliable from a normal elevated interactive admin session.' -Remediation 'Open an elevated Command Prompt as an admin user and run: certreq -q -enrollaik -config "".'
            }
            else {
                Add-Result -Category $Category -Check 'AIK test context' -Status 'INFO' -Result $identityName -Details 'Running the AIK certreq test from the current interactive context.'
            }
        }
        catch { }

        # Keep this close to the original script logic:
        # $certcmd = (cmd.exe /c "certreq -q -enrollaik -config """)
        # Retry while certreq returns the SCEP parse error, stop when a cert is returned or after the max attempts.
        $certreqCommand = 'certreq -q -enrollaik -config ""'
        $cmdArguments = '/d /c ' + $certreqCommand

        $scepParseStillHappening = $true

        for ($i = 1; ($i -le $AttemptCount) -and $scepParseStillHappening; $i++) {
            Write-AppLog -Message ('Fetching test AIK certificate attempt {0} with cmd.exe /d /c certreq -q -enrollaik -config ""' -f $i) -Level 'DEBUG'
            Add-Result -Category $Category -Check 'AIK certreq attempt' -Status 'INFO' -Result "Attempt $i" -Details 'Fetching test AIK certificate with certreq -q -enrollaik -config "".'
            Update-ProgressWindow -Message "AIK certreq test - attempt $i of $AttemptCount" -Detail 'Running cmd.exe /d /c certreq -q -enrollaik -config "" ...'

            $result = Invoke-ProcessHidden -FilePath $cmd -Arguments $cmdArguments -TimeoutSeconds 90
            $text = @($result.Output, $result.Error) -join [Environment]::NewLine
            $lastText = $text

            # ---------------------------------------------------------------
            # Impersonation error: certreq can't elevate to the level needed
            # by CertEnroll.dll::EnrollForAIKCertificate when launched from a
            # user session. Retry transparently as SYSTEM via a scheduled task.
            # ---------------------------------------------------------------
            if (Test-IsAikImpersonationError -Text $text) {
                Add-Result -Category $Category -Check 'AIK test context' -Status 'INFO' -Result 'Retrying as SYSTEM' -Details 'certreq returned 0x80070542 ERROR_BAD_IMPERSONATION_LEVEL from the current user context. CertEnroll.dll::EnrollForAIKCertificate needs a higher impersonation level. Relaunching certreq as SYSTEM via a one-shot scheduled task.'

                Write-AppLog -Message 'Impersonation error detected. Launching certreq as SYSTEM via scheduled task.' -Level 'DEBUG'
                Update-ProgressWindow -Message 'Relaunching certreq as SYSTEM via scheduled task...' -Detail 'Registering one-shot task as NT AUTHORITY\SYSTEM. Waiting for output (up to 120s).'
                $systemResult = Invoke-AikCertreqAsSystem

                try {
                    # Always clean up the temp folder
                    if ($systemResult.TempFolder -and (Test-Path $systemResult.TempFolder)) {
                        Remove-Item -Path $systemResult.TempFolder -Recurse -Force -ErrorAction SilentlyContinue
                    }
                } catch { }

                if (-not [string]::IsNullOrWhiteSpace($systemResult.Error)) {
                    Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'SYSTEM relaunch failed' -Details "Could not relaunch certreq as SYSTEM: $($systemResult.Error)" -Remediation 'Check that the Task Scheduler service is running and that the tool is running elevated.'
                    if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test SYSTEM relaunch failed' -Text $systemResult.Error -Urls @() -ImpersonationContext $true }
                    return
                }

                $systemText = $systemResult.Output
                $lastText   = $systemText
                $lastUrls   = @(Get-UrlsFromText -Text $systemText)

                if (Test-IsAikImpersonationError -Text $systemText) {
                    # Still failing even as SYSTEM - genuinely unexpected
                    Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'Impersonation error (SYSTEM)' -Details 'certreq returned 0x80070542 ERROR_BAD_IMPERSONATION_LEVEL even when running as SYSTEM. This is unusual and may indicate a TPM driver or CertEnroll issue.' -Remediation 'Export TPM logs, check CertificateServicesClient logs, and contact support.'
                    if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test impersonation error (SYSTEM)' -Text $systemText -Urls $lastUrls -ImpersonationContext $true }
                    return
                }

                Add-Result -Category $Category -Check 'AIK test context' -Status 'PASS' -Result 'SYSTEM relaunch succeeded' -Details 'certreq was relaunched as SYSTEM via a scheduled task. The output below is from the SYSTEM context run.'

                # Now parse the SYSTEM run output through the normal flow
                $text = $systemText
                $lastUrls = @(Get-UrlsFromText -Text $text)
            }
            # ---------------------------------------------------------------

            if ($lastUrls.Count -gt 0) {
                Add-Result -Category $Category -Check 'AIK CA URL from certreq' -Status 'INFO' -Result "URL(s)=$($lastUrls.Count)" -Details ($lastUrls -join '; ')
            }

            $hints = @(Get-AikAuthorityHintsFromText -Text $text)
            if ((-not $trustedTpmChecked) -and ($hints.Count -gt 0)) {
                Test-AikAuthorityAgainstTrustedTpmCab -Text $text -Urls $lastUrls -Category $Category
                $trustedTpmChecked = $true
            }

            $cacapsError = ($text -match 'GetCACaps:\s*Not\s*Found')
            if ($cacapsError) {
                Add-Result -Category $Category -Check 'AIK CA URL' -Status 'FAIL' -Result 'GetCACaps Not Found' -Details "certreq reported GetCACaps: Not Found. URL(s): $($lastUrls -join '; ')" -Remediation 'The AIK CA URL returned by certreq is not valid or is no longer reachable.'
                if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test failed' -Text $text -Urls $lastUrls }
                return
            }
            else {
                Add-Result -Category $Category -Check 'AIK CA URL' -Status 'PASS' -Result 'No GetCACaps error' -Details 'certreq did not report GetCACaps: Not Found.'
            }

            $scepParseStillHappening = ($text -match '\{"Message":"Failed to parse SCEP request\."\}|Failed to parse SCEP request')

            if ($text -match '-----BEGIN CERTIFICATE-----' -and $text -match '-----END CERTIFICATE-----') {
                $foundCertificate = $true
                $scepParseStillHappening = $false

                $aikCert = Convert-PemBlockToCertificate -Text $text
                if ($null -ne $aikCert) {
                    Add-Result -Category $Category -Check $CheckName -Status 'PASS' -Result 'AIK cert returned' -Details "Test AIK certificate returned on attempt $i. Thumbprint: $($aikCert.Thumbprint). Subject: $($aikCert.Subject). Issuer: $($aikCert.Issuer). NotAfter: $($aikCert.NotAfter)."
                }
                else {
                    Add-Result -Category $Category -Check $CheckName -Status 'PASS' -Result 'AIK cert returned' -Details "Test AIK certificate text returned on attempt $i."
                }

                if ((-not $trustedTpmChecked) -and ($hints.Count -gt 0)) {
                    Test-AikAuthorityAgainstTrustedTpmCab -Text $text -Urls $lastUrls -Category $Category
                    $trustedTpmChecked = $true
                }

                if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test certificate result' -Text $text -Urls $lastUrls -Certificate $aikCert }
                return
            }

            if ($scepParseStillHappening) {
                if ($i -lt $AttemptCount) {
                    Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'SCEP parse failed' -Details "Attempt $i returned Failed to parse SCEP request. Retrying, just like the original script did."
                    Start-SleepWithDoEvents -Seconds 2
                }
                else {
                    Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'SCEP parse failed' -Details "Retried $AttemptCount times. certreq kept returning Failed to parse SCEP request." -Remediation 'Retry after TPM maintenance and verify EK certificate state.'
                }
            }
            else {
                Write-AppLog -Message "certreq AIK attempt $i did not return a certificate. ExitCode=$($result.ExitCode). Output: $text" -Level 'DEBUG'
            }
        }

        if (-not $foundCertificate) {
            Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'No AIK cert' -Details "No test AIK certificate returned after $AttemptCount attempt(s). URL(s): $($lastUrls -join '; ')" -Remediation 'Check AIK enrollment logs, CertificateServicesClient logs, and tpmtool getdeviceinformation.'
            if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test result' -Text $lastText -Urls $lastUrls }
        }
    }
    catch {
        Add-Result -Category $Category -Check $CheckName -Status 'WARN' -Result 'Test failed' -Details $_.Exception.Message
        if ($ShowPopup) { Show-AikTestOutputWindow -Title 'AIK test error' -Text $_.Exception.Message -Urls $lastUrls }
    }
}

function Show-AikTestOutputWindow {
    param(
        [string]$Title = 'AIK test certificate result',
        [AllowNull()][string]$Text,
        [AllowNull()]$Urls,
        [AllowNull()]$Certificate,
        [switch]$ImpersonationContext
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.ClientSize = New-Object System.Drawing.Size(980, 620)
    $form.StartPosition = 'CenterParent'
    $form.MinimumSize = New-Object System.Drawing.Size(760, 460)
    $form.BackColor = [System.Drawing.Color]::White

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    $layout.RowCount = 4
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 110)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 46)) | Out-Null
    $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 1)) | Out-Null
    $form.Controls.Add($layout)

    $summary = New-Object System.Windows.Forms.TextBox
    $summary.Dock = 'Fill'
    $summary.Multiline = $true
    $summary.ReadOnly = $true
    $summary.BorderStyle = 'None'
    $summary.BackColor = [System.Drawing.Color]::White
    $summary.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $summaryLines = New-Object System.Collections.Generic.List[string]
    $summaryLines.Add('Command: cmd.exe /d /c certreq -q -enrollaik -config ""') | Out-Null
    if ($ImpersonationContext) {
        $summaryLines.Add('AIK URL(s): not applicable - certreq failed at the impersonation level before reaching the CA lookup stage.') | Out-Null
    }
    elseif ($Urls -and @($Urls).Count -gt 0) {
        $summaryLines.Add("AIK URL(s): $(@($Urls) -join '; ')") | Out-Null
    }
    else {
        $summaryLines.Add('AIK URL(s): none detected in certreq output') | Out-Null
    }

    if ($Certificate) {
        $summaryLines.Add("Returned certificate: $($Certificate.Thumbprint)") | Out-Null
        $summaryLines.Add("Subject: $($Certificate.Subject)") | Out-Null
        $summaryLines.Add("Issuer: $($Certificate.Issuer)") | Out-Null
    }

    $summary.Text = ($summaryLines -join [Environment]::NewLine)
    $layout.Controls.Add($summary, 0, 0)

    $output = New-Object System.Windows.Forms.TextBox
    $output.Dock = 'Fill'
    $output.Multiline = $true
    $output.ScrollBars = 'Both'
    $output.ReadOnly = $true
    $output.Font = New-Object System.Drawing.Font('Consolas', 9)
    $output.Text = [string]$Text
    $layout.Controls.Add($output, 0, 1)

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'
    $buttons.FlowDirection = 'RightToLeft'
    $buttons.Padding = New-Object System.Windows.Forms.Padding(8)
    $layout.Controls.Add($buttons, 0, 2)

    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'
    $close.Width = 90
    $close.Height = 28
    $close.Add_Click({ $form.Close() })
    $buttons.Controls.Add($close)

    $copy = New-Object System.Windows.Forms.Button
    $copy.Text = 'Copy output'
    $copy.Width = 110
    $copy.Height = 28
    $copy.Add_Click({ [System.Windows.Forms.Clipboard]::SetText($output.Text) })
    $buttons.Controls.Add($copy)

    [void]$form.ShowDialog()
}


function Invoke-PostAttestationResultChecks {
    param(
        [switch]$UseProgress
    )

    $category = 'Attestation Result'

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Validating TPM base state' -Detail 'Reading the current TPM state after the attestation actions.' -Step
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $stateDetails = "Present=$($tpm.TpmPresent); Ready=$($tpm.TpmReady); Owned=$($tpm.TpmOwned); Enabled=$($tpm.TpmEnabled); Activated=$($tpm.TpmActivated)"

        if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmOwned) {
            Add-Result -Category $category -Check 'Current TPM state' -Status 'PASS' -Details $stateDetails
        }
        else {
            Add-Result -Category $category -Check 'Current TPM state' -Status 'FAIL' -Details $stateDetails -Remediation 'Check BIOS TPM state, TPM ownership, and Windows TPM provisioning state.'
        }
    }
    catch {
        Add-Result -Category $category -Check 'Current TPM state' -Status 'FAIL' -Details $_.Exception.Message -Remediation 'Check TPM cmdlet availability and WMI health.'
    }

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Validating ready information' -Detail 'Calling Win32_TPM IsReadyInformation after the attestation actions.' -Step
    }

    $tpmCim = Get-TpmCimInstanceSafe
    if (-not $tpmCim) {
        Add-Result -Category $category -Check 'Ready information after kickstart' -Status 'FAIL' -Details 'Win32_TPM could not be queried.' -Remediation 'Check TPM WMI provider health.'
    }
    else {
        try {
            $attestation = $tpmCim | Invoke-CimMethod -MethodName IsReadyInformation -ErrorAction Stop
            $code = [int64]$attestation.Information

            if ($code -eq 0) {
                Add-Result -Category $category -Check 'Ready information after kickstart' -Status 'PASS' -Details 'IsReadyInformation returned 0. TPM reports ready for attestation.'
            }
            else {
                $known = switch ($code) {
                    262144   { 'EK certificate appears to be missing.' }
                    16777216 { 'TPM health attestation vulnerability state was reported.' }
                    default  { "IsReadyInformation returned $code." }
                }

                Add-Result -Category $category -Check 'Ready information after kickstart' -Status 'FAIL' -Details $known -Remediation 'Export TPM logs, check EK certificate retrieval, and rerun the checks after a reboot if needed.'
            }
        }
        catch {
            Add-Result -Category $category -Check 'Ready information after kickstart' -Status 'FAIL' -Details $_.Exception.Message -Remediation 'Check TPM WMI provider health.'
        }
    }

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Validating key attestation capability' -Detail 'Calling Win32_TPM IsKeyAttestationCapable after the attestation actions.' -Step
    }

    if (-not $tpmCim) {
        Add-Result -Category $category -Check 'Key attestation capable after kickstart' -Status 'FAIL' -Details 'Win32_TPM could not be queried.' -Remediation 'Check TPM WMI provider health.'
    }
    else {
        try {
            $capable = $tpmCim | Invoke-CimMethod -MethodName IsKeyAttestationCapable -ErrorAction Stop
            $code = [int64]$capable.TestResult

            if ($code -eq 0) {
                Add-Result -Category $category -Check 'Key attestation capable after kickstart' -Status 'PASS' -Details 'IsKeyAttestationCapable returned 0.'
            }
            else {
                Add-Result -Category $category -Check 'Key attestation capable after kickstart' -Status 'FAIL' -Details "IsKeyAttestationCapable returned $code." -Remediation 'Run tpmtool getdeviceinformation and review TPM capability output.'
            }
        }
        catch {
            Add-Result -Category $category -Check 'Key attestation capable after kickstart' -Status 'FAIL' -Details $_.Exception.Message -Remediation 'Check TPM WMI provider health.'
        }
    }

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Validating EK certificate result' -Detail 'Reading Get-TpmEndorsementKeyInfo after the attestation actions.' -Step
    }

    try {
        $ekInfo = Get-TpmEndorsementKeyInfo -ErrorAction Stop
        $manufacturerCerts = @()
        $additionalCerts = @()

        if ($ekInfo.ManufacturerCertificates) {
            $manufacturerCerts = @($ekInfo.ManufacturerCertificates)
        }

        if ($ekInfo.AdditionalCertificates) {
            $additionalCerts = @($ekInfo.AdditionalCertificates)
        }

        $certCount = $manufacturerCerts.Count + $additionalCerts.Count

        if ($ekInfo.IsPresent -and $certCount -gt 0) {
            Add-Result -Category $category -Check 'EK certificate result after kickstart' -Status 'PASS' -Details "Endorsement key present. ManufacturerCertificates=$($manufacturerCerts.Count); AdditionalCertificates=$($additionalCerts.Count)."

            $allEkCerts = @()
            $allEkCerts += $manufacturerCerts
            $allEkCerts += $additionalCerts
            $firstCert = $allEkCerts | Select-Object -First 1

            if ($null -ne $firstCert) {
                Add-Result -Category $category -Check 'First EK certificate' -Status 'INFO' -Details "Thumbprint: $($firstCert.Thumbprint). Subject: $($firstCert.Subject)"
            }
        }
        elseif ($ekInfo.IsPresent) {
            Add-Result -Category $category -Check 'EK certificate result after kickstart' -Status 'FAIL' -Details 'Endorsement key is present, but no ManufacturerCertificates or AdditionalCertificates were returned.' -Remediation 'Check vendor EK retrieval endpoint access and TPM event logs.'
        }
        else {
            Add-Result -Category $category -Check 'EK certificate result after kickstart' -Status 'FAIL' -Details 'Endorsement key is not present.' -Remediation 'Check TPM provisioning state and firmware settings.'
        }
    }
    catch {
        Add-Result -Category $category -Check 'EK certificate result after kickstart' -Status 'WARN' -Details $_.Exception.Message -Remediation 'Run Get EK certs and export TPM logs for more detail.'
    }

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Validating AIK enrollment result' -Detail 'Reading the AIKCertEnroll ErrorCode registry value.' -Step
    }

    try {
        $aikReg = 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\AIKCertEnroll'
        $aikProps = Get-ItemProperty -Path $aikReg -Name 'ErrorCode' -ErrorAction SilentlyContinue

        if ($null -eq $aikProps) {
            Add-Result -Category $category -Check 'AIK enrollment result after kickstart' -Status 'WARN' -Details 'AIK ErrorCode registry value was not found.' -Remediation 'Check CertificateServicesClient and TPM event logs.'
        }
        elseif ([int64]$aikProps.ErrorCode -eq 0) {
            Add-Result -Category $category -Check 'AIK enrollment result after kickstart' -Status 'PASS' -Details 'AIK ErrorCode is 0.'
        }
        else {
            Add-Result -Category $category -Check 'AIK enrollment result after kickstart' -Status 'FAIL' -Details "AIK ErrorCode: $($aikProps.ErrorCode)" -Remediation 'Check CertificateServicesClient logs, TPM logs, and tpmtool getdeviceinformation output.'
        }
    }
    catch {
        Add-Result -Category $category -Check 'AIK enrollment result after kickstart' -Status 'WARN' -Details $_.Exception.Message -Remediation 'Check if the AIKCertEnroll registry path exists on this Windows build.'
    }

    if ($UseProgress) {
        Update-ProgressWindow -Message 'Testing AIK certificate enrollment' -Detail 'Running cmd.exe /d /c certreq -q -enrollaik -config "". This matches the Command Prompt based AIK test.' -Step
    }
    Test-AikTestCertificate -Category $category -CheckName 'Test AIK certificate after kickstart' -AttemptCount 10
}

function Invoke-TpmAttestationAction {
    if (-not (Test-IsAdmin)) {
        [System.Windows.Forms.MessageBox]::Show('Run this tool as administrator before starting TPM attestation actions.', 'Admin required', 'OK', 'Warning') | Out-Null
        return
    }

    Start-ProgressWindow -Title 'Running TPM attestation actions' -Maximum 18 -Message 'Starting TPM attestation actions...'

    try {
        Add-Result -Category 'Attestation Action' -Check 'Attestation flow started' -Status 'INFO' -Result 'Started' -Details 'Starting TPM maintenance, EK retrieval, Windows AIK creation, AIK enrollment, and a certreq test AIK validation.'

        Update-ProgressWindow -Message 'Setting OOBE EULA marker' -Detail 'Required on some builds before TPM maintenance will retrieve EK material.' -Step
        try {
            $oobePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE'
            if (-not (Test-Path $oobePath)) {
                New-Item -Path $oobePath -Force | Out-Null
            }

            New-ItemProperty -Path $oobePath -Name 'SetupDisplayedEula' -Value 1 -PropertyType DWord -Force | Out-Null
            Add-Result -Category 'Attestation Action' -Check 'SetupDisplayedEula' -Status 'PASS' -Details 'SetupDisplayedEula was set to 1.'
        }
        catch {
            Add-Result -Category 'Attestation Action' -Check 'SetupDisplayedEula' -Status 'WARN' -Details $_.Exception.Message
        }

        Update-ProgressWindow -Message 'Starting TPM maintenance task' -Detail 'Running Microsoft\Windows\TPM\Tpm-Maintenance.' -Step
        try {
            Start-ScheduledTask -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -ErrorAction Stop
            Start-SleepWithDoEvents -Seconds 5
            $taskInfo = Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -ErrorAction SilentlyContinue

            if ($taskInfo -and $taskInfo.LastTaskResult -eq 0) {
                Add-Result -Category 'Attestation Action' -Check 'TPM maintenance task' -Status 'PASS' -Details 'TPM maintenance task completed with LastTaskResult 0.'
            }
            else {
                $lastResult = if ($taskInfo) { $taskInfo.LastTaskResult } else { 'Unknown' }
                Add-Result -Category 'Attestation Action' -Check 'TPM maintenance task' -Status 'WARN' -Details "LastTaskResult: $lastResult" -Remediation 'Continue with TPM attestation actions and recheck.'
            }
        }
        catch {
            Add-Result -Category 'Attestation Action' -Check 'TPM maintenance task' -Status 'WARN' -Details $_.Exception.Message
        }

        $functions = @(
            [PSCustomObject]@{ Name = 'TpmProvision'; Timeout = 60; Purpose = 'TPM provisioning state' },
            [PSCustomObject]@{ Name = 'TpmCertInstallNvEkCerts'; Timeout = 60; Purpose = 'Install EK certificates available in TPM NV' },
            [PSCustomObject]@{ Name = 'TpmCertGetEkCertFromWeb'; Timeout = 90; Purpose = 'Retrieve EK certificate from the vendor or Microsoft EK endpoint' },
            [PSCustomObject]@{ Name = 'TpmRetrieveEkCertOrReschedule'; Timeout = 90; Purpose = 'Retrieve or schedule EK certificate retrieval' },
            [PSCustomObject]@{ Name = 'TpmCheckCreateWindowsAIK'; Timeout = 60; Purpose = 'Create or validate Windows AIK' },
            [PSCustomObject]@{ Name = 'TpmEnrollWindowsAikCertificate'; Timeout = 90; Purpose = 'Enroll Windows AIK certificate' }
        )

        foreach ($function in $functions) {
            Update-ProgressWindow -Message "Running $($function.Name)" -Detail $function.Purpose -Step
            Invoke-TpmCoreProvisioningFunction -FunctionName $function.Name -TimeoutSeconds $function.Timeout
            Start-SleepWithDoEvents -Seconds 1
        }

        Update-ProgressWindow -Message 'Starting AIK enrollment task' -Detail 'Running Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask.' -Step
        try {
            Start-ScheduledTask -TaskPath '\Microsoft\Windows\CertificateServicesClient\' -TaskName 'AikCertEnrollTask' -ErrorAction Stop
            Add-Result -Category 'Attestation Action' -Check 'AIK enrollment task' -Status 'PASS' -Details 'AIKCertEnrollTask was started.'
        }
        catch {
            Add-Result -Category 'Attestation Action' -Check 'AIK enrollment task' -Status 'WARN' -Details $_.Exception.Message
        }

        Update-ProgressWindow -Message 'Waiting for TPM state to settle' -Detail 'Giving the TPM tasks a few seconds to update WMI and registry state.' -Step
        Start-SleepWithDoEvents -Seconds 5

        Invoke-PostAttestationResultChecks -UseProgress

        Update-FinalSummary
        Update-ProgressWindow -Message 'Done' -Detail 'TPM attestation actions completed. Post action result rows were added to the grid.'
    }
    finally {
        Start-SleepWithDoEvents -Seconds 1
        Close-ProgressWindow
    }
}

function Invoke-TpmToolDeviceInformation {
    $tpmTool = Resolve-LocalOrInboxFile -FileName 'TpmTool.exe' -InboxPath (Join-Path $env:WINDIR 'System32\tpmtool.exe')

    if (-not $tpmTool) {
        Add-Result -Category 'TPM Tool' -Check 'tpmtool getdeviceinformation' -Status 'WARN' -Details 'tpmtool.exe was not found.'
        return
    }

    $result = Invoke-ProcessHidden -FilePath $tpmTool -Arguments 'getdeviceinformation' -TimeoutSeconds 60
    $text = @($result.Output, $result.Error) -join [Environment]::NewLine

    if ($result.ExitCode -eq 0) {
        Add-Result -Category 'TPM Tool' -Check 'tpmtool getdeviceinformation' -Status 'INFO' -Details 'Command completed. See log output.'
        Write-AppLog -Message $text -Level 'DEBUG'
    }
    else {
        Add-Result -Category 'TPM Tool' -Check 'tpmtool getdeviceinformation' -Status 'WARN' -Details "Exit code $($result.ExitCode). See log output."
        Write-AppLog -Message $text -Level 'DEBUG'
    }
}

function Invoke-WindowsUpdateCheck {
    # Re-introduced from the v0.11 test-requiredupdates function, rewritten to use Add-Result
    # and the progress window instead of Read-Host. Called on demand via its own toolbar button.
    if (-not (Test-IsAdmin)) {
        [System.Windows.Forms.MessageBox]::Show('Run this tool as administrator before scanning for Windows Updates.', 'Admin required', 'OK', 'Warning') | Out-Null
        return
    }

    Start-ProgressWindow -Title 'Scanning for Windows Updates' -Maximum 3 -Message 'Connecting to Windows Update...'

    try {
        Update-ProgressWindow -Message 'Creating Windows Update session' -Detail 'Using Microsoft.Update.Session COM object.' -Step
        $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()

        Update-ProgressWindow -Message 'Searching for uninstalled cumulative updates' -Detail 'This may take up to a minute. Searching IsAssigned=1 IsHidden=0 IsInstalled=0.' -Step
        $results = $searcher.Search('IsAssigned=1 and IsHidden=0 and IsInstalled=0')
        $pending = @($results.Updates | Where-Object {
            ($_.Title -like '*Windows 10*' -or $_.Title -like '*Windows 11*') -and
            $_.Title -notlike '*.Net Framework*' -and
            $_.Title -notlike '*2022-04*'    # exclude known false positive
        })

        Update-ProgressWindow -Message 'Processing results' -Detail "$($pending.Count) pending cumulative update(s) found." -Step
        Close-ProgressWindow

        if ($pending.Count -eq 0) {
            Add-Result -Category 'Windows Update' -Check 'Cumulative update status' -Status 'PASS' -Details 'No pending Windows 10/11 cumulative updates found. Device appears up to date.'
        }
        else {
            foreach ($update in $pending) {
                Add-Result -Category 'Windows Update' -Check 'Pending update' -Status 'FAIL' -Details $update.Title -Remediation 'Install all pending cumulative updates before performing Autopilot pre-provisioning. Some updates include critical TPM fixes.'
            }

            $answer = [System.Windows.Forms.MessageBox]::Show(
                "$($pending.Count) pending cumulative update(s) found.`n`nDo you want to open Windows Update now?",
                'Pending Windows Updates',
                'YesNo',
                'Warning'
            )
            if ($answer -eq 'Yes') {
                Start-Process 'ms-settings:windowsupdate'
            }
        }

        Update-FinalSummary
    }
    catch {
        Close-ProgressWindow
        Add-Result -Category 'Windows Update' -Check 'Update scan' -Status 'WARN' -Details "Windows Update scan failed: $($_.Exception.Message)" -Remediation 'Try opening Windows Update manually and verify connectivity to Microsoft Update servers.'
    }
}

function Invoke-AllChecks {
    Start-ProgressWindow -Title 'Running TPM attestation checks' -Maximum 17 -Message 'Starting TPM attestation checks...'

    try {
        Update-ProgressWindow -Message 'Checking administrator context' -Detail 'The tool needs elevation for HKLM, scheduled tasks, and TPM checks.' -Step

        if (-not (Test-IsAdmin)) {
            Reset-Results
            Add-Result -Category 'Startup' -Check 'Administrator' -Status 'FAIL' -Details 'Tool is not running elevated.' -Remediation 'Restart PowerShell as administrator.'
            Update-FinalSummary
            return
        }

        Reset-Results

        Add-Result -Category 'Startup' -Check 'Administrator' -Status 'PASS' -Details 'Tool is running elevated.'

        Update-ProgressWindow -Message 'Checking TPM helper files' -Detail 'Looking for inbox TPM helper files or local fallback files.' -Step
        Test-TpmHelperFiles

        Update-ProgressWindow -Message 'Reading hardware information' -Detail 'Using CIM instead of WMIC.' -Step
        Test-HardwareInfo

        Update-ProgressWindow -Message 'Checking Windows license information' -Detail 'Reading SoftwareLicensingService through CIM.' -Step
        Test-WindowsLicense

        Update-ProgressWindow -Message 'Checking Windows Time' -Detail 'Time drift can break certificate and attestation flows.' -Step
        Test-TimeService

        Update-ProgressWindow -Message 'Checking TPM and Autopilot endpoints' -Detail 'Testing required and vendor specific HTTPS endpoints.' -Step
        Test-ConnectivityChecks

        Update-ProgressWindow -Message 'Checking TPM base state' -Detail 'TPM present, enabled, activated, owned, and ready state.' -Step
        Test-TpmBaseState

        Update-ProgressWindow -Message 'Checking TPM firmware' -Detail 'Looking for known Infineon firmware issues.' -Step
        Test-InfineonFirmware

        Update-ProgressWindow -Message 'Checking measured boot logs' -Detail 'Verifying the WBCL registry value.' -Step
        Test-WbclPresence

        Update-ProgressWindow -Message 'Checking TPM maintenance state' -Detail 'Checking SetupDisplayedEula, TPM-Maintenance, and the EkCertificatePresent task state.' -Step
        Test-TpmMaintenanceReadiness

        Update-ProgressWindow -Message 'Checking EK certificate store' -Detail 'Verifying the TPM EK certificate registry store.' -Step
        Test-EkCertificateStore

        Update-ProgressWindow -Message 'Checking ready for attestation state' -Detail 'Calling Win32_TPM IsReadyInformation.' -Step
        Test-TpmReadyForAttestation

        Add-Result -Category 'AIK' -Check 'Ready flag versus real AIK test' -Status 'INFO' -Result 'Separate checks' -Details 'IsReadyInformation does not prove the device can actually receive an AIK certificate. The certreq AIK test below performs that extra validation.'

        Update-ProgressWindow -Message 'Checking key attestation capability' -Detail 'Calling Win32_TPM IsKeyAttestationCapable.' -Step
        Test-KeyAttestationCapable
        Update-ProgressWindow -Message 'Testing AIK certificate enrollment' -Detail 'Running the Command Prompt based certreq AIK enrollment test.' -Step
        Test-AikTestCertificate

        Update-ProgressWindow -Message 'Checking AIK enrollment task' -Detail 'Starting AikCertEnrollTask and reading the AIK error code.' -Step
        Test-AikEnrollmentTask

        Update-ProgressWindow -Message 'Collecting TPM tool details' -Detail 'Running tpmtool getdeviceinformation when available.' -Step
        Invoke-TpmToolDeviceInformation

        Update-FinalSummary
        Update-ProgressWindow -Message 'Done' -Detail 'TPM attestation checks completed.'
    }
    finally {
        Start-SleepWithDoEvents -Seconds 1
        Close-ProgressWindow
    }
}


function Get-SafeFileName {
    param([Parameter(Mandatory = $true)][string]$Name)
    return ($Name -replace '[\\/:*?"<>|]', '_')
}

function Export-RegistryKeySafe {
    param(
        [Parameter(Mandatory = $true)][string]$RegistryPath,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $regExe = Join-Path $env:WINDIR 'System32\reg.exe'
    $result = Invoke-ProcessHidden -FilePath $regExe -Arguments "export `"$RegistryPath`" `"$OutputPath`" /y" -TimeoutSeconds 60
    return $result
}

function Export-TpmEventLogs {
    if (-not (Test-IsAdmin)) {
        [System.Windows.Forms.MessageBox]::Show('Run this tool as administrator before exporting TPM logs.', 'Admin required', 'OK', 'Warning') | Out-Null
        return
    }

    Start-ProgressWindow -Title 'Exporting TPM logs' -Maximum 9 -Message 'Preparing TPM log export...'

    try {
        $root = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
        if (-not (Test-Path $root)) {
            New-Item -Path $root -ItemType Directory -Force | Out-Null
        }

        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $folder = Join-Path $root "TPM_Logs_$stamp"
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
        $script:LastExportFolder = $folder

        Add-Result -Category 'Export' -Check 'TPM log export' -Status 'INFO' -Details "Export folder: $folder"

        Update-ProgressWindow -Message 'Discovering TPM related event logs' -Detail 'Looking for TPM, TPM WMI, CertificateServicesClient, and CAPI2 logs.' -Step

        $logNames = New-Object System.Collections.Generic.List[string]
        $patterns = @(
            '*TPM*',
            'Microsoft-Windows-CertificateServicesClient*',
            'Microsoft-Windows-CAPI2/Operational'
        )

        foreach ($pattern in $patterns) {
            try {
                $foundLogs = @(Get-WinEvent -ListLog $pattern -ErrorAction SilentlyContinue)
                foreach ($log in $foundLogs) {
                    if ($log.LogName -and -not $logNames.Contains($log.LogName)) {
                        $logNames.Add($log.LogName) | Out-Null
                    }
                }
            }
            catch { }
        }

        if ($logNames.Count -eq 0) {
            Add-Result -Category 'Export' -Check 'Event log discovery' -Status 'WARN' -Details 'No TPM related event logs were discovered.' -Remediation 'Check Event Viewer manually for TPM and CertificateServicesClient logs.'
        }
        else {
            Add-Result -Category 'Export' -Check 'Event log discovery' -Status 'PASS' -Details "$($logNames.Count) event log(s) discovered."
        }

        Update-ProgressWindow -Message 'Exporting event logs' -Detail 'Writing EVTX files to the export folder.' -Step
        $wevtutil = Join-Path $env:WINDIR 'System32\wevtutil.exe'
        $exportedCount = 0

        foreach ($logName in $logNames) {
            $safeName = Get-SafeFileName -Name $logName
            $evtxPath = Join-Path $folder "$safeName.evtx"
            $result = Invoke-ProcessHidden -FilePath $wevtutil -Arguments "epl `"$logName`" `"$evtxPath`" /ow:true" -TimeoutSeconds 90

            if ($result.ExitCode -eq 0 -and (Test-Path $evtxPath)) {
                $exportedCount++
                Write-AppLog -Message "Exported event log $logName to $evtxPath" -Level 'DEBUG'
            }
            else {
                Write-AppLog -Message "Could not export event log $logName. ExitCode=$($result.ExitCode). $($result.Error)" -Level 'WARN'
            }
        }

        if ($exportedCount -gt 0) {
            Add-Result -Category 'Export' -Check 'EVTX export' -Status 'PASS' -Details "$exportedCount event log(s) exported."
        }
        else {
            Add-Result -Category 'Export' -Check 'EVTX export' -Status 'WARN' -Details 'No event logs were exported.' -Remediation 'Open Event Viewer and verify TPM logs manually.'
        }

        Update-ProgressWindow -Message 'Exporting recent TPM events as CSV' -Detail 'Creating a quick readable event summary.' -Step
        $eventSummaryPath = Join-Path $folder 'Recent_TPM_Events.csv'
        $events = New-Object System.Collections.Generic.List[object]

        foreach ($logName in $logNames) {
            try {
                $recent = @(Get-WinEvent -LogName $logName -MaxEvents 200 -ErrorAction SilentlyContinue)
                foreach ($event in $recent) {
                    $events.Add([PSCustomObject]@{
                        LogName      = $logName
                        TimeCreated  = $event.TimeCreated
                        Id           = $event.Id
                        Level        = $event.LevelDisplayName
                        ProviderName = $event.ProviderName
                        Message      = (($event.Message -replace "`r|`n", ' ') -replace '\s+', ' ').Trim()
                    }) | Out-Null
                }
            }
            catch { }
        }

        if ($events.Count -gt 0) {
            $events | Sort-Object TimeCreated -Descending | Export-Csv -Path $eventSummaryPath -NoTypeInformation -Encoding UTF8
            Add-Result -Category 'Export' -Check 'Readable event summary' -Status 'PASS' -Details "$($events.Count) recent event(s) exported to CSV."
        }
        else {
            Add-Result -Category 'Export' -Check 'Readable event summary' -Status 'WARN' -Details 'No recent events were exported to CSV.'
        }

        Update-ProgressWindow -Message 'Collecting TPM tool output' -Detail 'Running tpmtool getdeviceinformation when available.' -Step
        $tpmTool = Resolve-LocalOrInboxFile -FileName 'TpmTool.exe' -InboxPath (Join-Path $env:WINDIR 'System32\tpmtool.exe')
        if ($tpmTool) {
            $tpmToolResult = Invoke-ProcessHidden -FilePath $tpmTool -Arguments 'getdeviceinformation' -TimeoutSeconds 60
            $tpmToolPath = Join-Path $folder 'TpmTool_GetDeviceInformation.txt'
            @(
                "TPM Tool: $tpmTool"
                "ExitCode: $($tpmToolResult.ExitCode)"
                ''
                'STDOUT:'
                $tpmToolResult.Output
                ''
                'STDERR:'
                $tpmToolResult.Error
            ) | Set-Content -Path $tpmToolPath -Encoding UTF8
            Add-Result -Category 'Export' -Check 'TPM tool output' -Status 'PASS' -Details 'tpmtool getdeviceinformation output exported.'
        }
        else {
            Add-Result -Category 'Export' -Check 'TPM tool output' -Status 'WARN' -Details 'tpmtool.exe was not found.'
        }

        Update-ProgressWindow -Message 'Exporting EK certificate details' -Detail 'Saving ManufacturerCertificates, AdditionalCertificates, and chain details when available.' -Step
        $ekCertObjects = @(Get-TpmEndorsementCertificateObjects)
        $ekCerts = New-Object System.Collections.Generic.List[object]
        foreach ($item in $ekCertObjects) {
            try {
                $ekCerts.Add((Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type)) | Out-Null
            }
            catch { }
        }

        if ($ekCerts.Count -gt 0) {
            $ekCertPath = Join-Path $folder 'TPM_Endorsement_Certificates.csv'
            $ekCerts | Export-Csv -Path $ekCertPath -NoTypeInformation -Encoding UTF8
            Add-Result -Category 'Export' -Check 'EK certificate details' -Status 'PASS' -Details "$($ekCerts.Count) endorsement certificate(s) exported."

            $allEkCertificateObjects = @($ekCertObjects | ForEach-Object { $_.Certificate })
            $chainExportRows = New-Object System.Collections.Generic.List[object]
            foreach ($item in $ekCertObjects) {
                try {
                    $display = Convert-CertificateForDisplay -Certificate $item.Certificate -Type $item.Type
                    $chainRows = @(Get-CertificateChainReport -Certificate $item.Certificate -AllCertificates $allEkCertificateObjects)
                    foreach ($chainRow in $chainRows) {
                        $chainExportRows.Add([PSCustomObject]@{
                            SourceType           = $item.Type
                            SourceThumbprint     = $display.Thumbprint
                            SourceSubject        = $display.Subject
                            Level                = $chainRow.Level
                            ChainBuildSucceeded  = $chainRow.ChainBuildSucceeded
                            OverallStatus        = $chainRow.OverallStatus
                            ElementStatus        = $chainRow.ElementStatus
                            Thumbprint           = $chainRow.Thumbprint
                            Subject              = $chainRow.Subject
                            Issuer               = $chainRow.Issuer
                            SerialNumber         = $chainRow.SerialNumber
                            NotBefore            = $chainRow.NotBefore
                            NotAfter             = $chainRow.NotAfter
                            SignatureAlgorithm   = $chainRow.SignatureAlgorithm
                            PublicKeyAlgorithm   = $chainRow.PublicKeyAlgorithm
                            KeySize              = $chainRow.KeySize
                            IsSelfSigned         = $chainRow.IsSelfSigned
                        }) | Out-Null
                    }
                }
                catch { }
            }

            if ($chainExportRows.Count -gt 0) {
                $chainPath = Join-Path $folder 'TPM_Endorsement_Certificate_Chains.csv'
                $chainExportRows | Export-Csv -Path $chainPath -NoTypeInformation -Encoding UTF8
                Add-Result -Category 'Export' -Check 'EK certificate chains' -Status 'PASS' -Details "$($chainExportRows.Count) chain row(s) exported."
            }
        }
        else {
            Add-Result -Category 'Export' -Check 'EK certificate details' -Status 'WARN' -Details 'No endorsement certificate details were exported.'
        }

        Update-ProgressWindow -Message 'Exporting TPM registry context' -Detail 'Exporting AIK, TPM WMI, IntegrityServices, and OOBE keys when present.' -Step
        $registryExports = @(
            [PSCustomObject]@{ Path = 'HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\AIKCertEnroll'; File = 'AIKCertEnroll.reg' },
            [PSCustomObject]@{ Path = 'HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI'; File = 'TPM_WMI.reg' },
            [PSCustomObject]@{ Path = 'HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices'; File = 'IntegrityServices.reg' },
            [PSCustomObject]@{ Path = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE'; File = 'OOBE.reg' }
        )

        $regCount = 0
        foreach ($item in $registryExports) {
            $outPath = Join-Path $folder $item.File
            $result = Export-RegistryKeySafe -RegistryPath $item.Path -OutputPath $outPath
            if ($result.ExitCode -eq 0 -and (Test-Path $outPath)) {
                $regCount++
            }
            else {
                Write-AppLog -Message "Registry export skipped or failed for $($item.Path). ExitCode=$($result.ExitCode). $($result.Error)" -Level 'DEBUG'
            }
        }
        Add-Result -Category 'Export' -Check 'Registry context' -Status 'INFO' -Details "$regCount registry export(s) created."

        Update-ProgressWindow -Message 'Exporting current tool results' -Detail 'Saving the visible grid and log output.' -Step
        $resultsPath = Join-Path $folder 'Tool_Results.csv'
        $logPath = Join-Path $folder 'Tool_Log.txt'
        $script:Results | Export-Csv -Path $resultsPath -NoTypeInformation -Encoding UTF8
        $script:LogLines | Set-Content -Path $logPath -Encoding UTF8

        Update-ProgressWindow -Message 'Opening export folder' -Detail $folder -Step
        Start-Process explorer.exe -ArgumentList "`"$folder`""

        Add-Result -Category 'Export' -Check 'Open folder' -Status 'PASS' -Details 'Export folder opened in Explorer.'
        Update-ProgressWindow -Message 'Done' -Detail 'TPM logs exported and opened.'
        [System.Windows.Forms.MessageBox]::Show("TPM logs exported and opened:`n$folder", 'TPM log export complete', 'OK', 'Information') | Out-Null
    }
    catch {
        Add-Result -Category 'Export' -Check 'TPM log export' -Status 'FAIL' -Details $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'TPM log export failed', 'OK', 'Error') | Out-Null
    }
    finally {
        Start-SleepWithDoEvents -Seconds 1
        Close-ProgressWindow
    }
}

function ConvertTo-HtmlEscape {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
}

function New-HtmlReport {
    param(
        [Parameter(Mandatory=$true)]$Results,
        [Parameter(Mandatory=$true)]$LogLines,
        [Parameter(Mandatory=$true)][string]$GeneratedAt
    )

    $failCount = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warnCount = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    $passCount = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $infoCount = @($Results | Where-Object { $_.Status -eq 'INFO' }).Count

    if ($failCount -gt 0) {
        $summaryState = 'BLOCKED'
        $summaryText  = "Not ready for TPM attestation - $failCount failed, $warnCount warning, $passCount passed"
        $summaryColor = '#c0392b'
        $summaryBg    = '#fdf0f0'
        $summaryBorder= '#e74c3c'
        $badgeEmoji   = '&#10060;'
    } elseif ($warnCount -gt 0) {
        $summaryState = 'WARNING'
        $summaryText  = "Warnings present - $warnCount warning, $passCount passed, no failures"
        $summaryColor = '#b7770d'
        $summaryBg    = '#fffbf0'
        $summaryBorder= '#f39c12'
        $badgeEmoji   = '&#9888;&#65039;'
    } elseif ($passCount -gt 0) {
        $summaryState = 'READY'
        $summaryText  = "Ready for TPM attestation - $passCount checks passed"
        $summaryColor = '#196f3d'
        $summaryBg    = '#f0fdf4'
        $summaryBorder= '#27ae60'
        $badgeEmoji   = '&#9989;'
    } else {
        $summaryState = 'IDLE'
        $summaryText  = 'No results'
        $summaryColor = '#555'
        $summaryBg    = '#f8f9fa'
        $summaryBorder= '#ccc'
        $badgeEmoji   = '&#8212;'
    }

    # Build result rows HTML
    $rowsHtml = New-Object System.Text.StringBuilder
    $prevCategory = ''
    foreach ($r in $Results) {
        $cat      = ConvertTo-HtmlEscape $r.Category
        $check    = ConvertTo-HtmlEscape $r.Check
        $status   = ConvertTo-HtmlEscape $r.Status
        $result   = ConvertTo-HtmlEscape $r.Result
        $details  = ConvertTo-HtmlEscape $r.Details
        $remediation = ConvertTo-HtmlEscape $r.Remediation

        $rowClass = switch ($r.Status) {
            'PASS' { 'row-pass' }
            'FAIL' { 'row-fail' }
            'WARN' { 'row-warn' }
            default { 'row-info' }
        }

        $statusBadge = switch ($r.Status) {
            'PASS' { '<span class="badge badge-pass">PASS</span>' }
            'FAIL' { '<span class="badge badge-fail">FAIL</span>' }
            'WARN' { '<span class="badge badge-warn">WARN</span>' }
            default { '<span class="badge badge-info">INFO</span>' }
        }

        $catCell = ''
        if ($cat -ne $prevCategory) {
            # Count how many rows share this category for rowspan
            $span = @($Results | Where-Object { $_.Category -eq $r.Category }).Count
            $catCell = "<td class=`"cat-cell`" rowspan=`"$span`">$cat</td>"
            $prevCategory = $cat
        }

        $remCell = if ([string]::IsNullOrWhiteSpace($r.Remediation)) { '<td class="rem-cell rem-empty">&mdash;</td>' } else { "<td class=`"rem-cell`">$remediation</td>" }

        [void]$rowsHtml.AppendLine("<tr class=`"$rowClass`">$catCell<td class=`"check-cell`">$check</td><td class=`"status-cell`">$statusBadge</td><td class=`"result-cell`">$result</td><td class=`"details-cell`">$details</td>$remCell</tr>")
    }

    # Build log HTML
    $logHtml = New-Object System.Text.StringBuilder
    foreach ($line in $LogLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $escaped = ConvertTo-HtmlEscape $line
        $lineClass = if ($line -match '\[FAIL\]') { 'log-fail' }
                     elseif ($line -match '\[WARN\]') { 'log-warn' }
                     elseif ($line -match '\[PASS\]') { 'log-pass' }
                     elseif ($line -match '\[DEBUG\]') { 'log-debug' }
                     else { 'log-info' }
        [void]$logHtml.AppendLine("<div class=`"log-line $lineClass`">$escaped</div>")
    }

    # Pre-escape CSS values so they are safe inside the here-string
    $cssBg     = $summaryBg
    $cssBorder = $summaryBorder
    $cssColor  = $summaryColor

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Autopilot TPM Attestation Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px; background: #f4f6f9; color: #1a1a2e; }

  .page-header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 60%, #0f3460 100%);
    color: #fff; padding: 28px 36px 24px;
  }
  .page-header h1 { font-size: 22px; font-weight: 700; letter-spacing: -.3px; }
  .page-header .meta { margin-top: 6px; font-size: 12px; opacity: .7; }

  .summary-bar {
    margin: 20px 28px 0;
    background: $cssBg;
    border: 2px solid $cssBorder;
    border-radius: 10px;
    padding: 16px 24px;
    display: flex; align-items: center; gap: 16px;
  }
  .summary-emoji { font-size: 28px; line-height: 1; }
  .summary-text { font-size: 15px; font-weight: 700; color: $cssColor; }
  .summary-chips { display: flex; gap: 8px; margin-left: auto; flex-wrap: wrap; }
  .chip { border-radius: 20px; padding: 4px 14px; font-size: 12px; font-weight: 700; }
  .chip-pass { background: #d4edda; color: #155724; }
  .chip-fail { background: #f8d7da; color: #721c24; }
  .chip-warn { background: #fff3cd; color: #856404; }
  .chip-info { background: #e2e3e5; color: #383d41; }

  .section { margin: 20px 28px; }
  .section-title { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: .8px; color: #555; margin-bottom: 10px; }

  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  thead th { background: #1a1a2e; color: #fff; padding: 10px 12px; text-align: left; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .6px; white-space: nowrap; }
  tbody tr { border-bottom: 1px solid #f0f0f0; }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(0,0,0,.02); }

  .cat-cell { padding: 10px 12px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #555; vertical-align: top; white-space: nowrap; border-right: 3px solid #e8ecf0; background: #fafbfc; }
  .check-cell { padding: 10px 12px; font-weight: 600; vertical-align: top; min-width: 160px; }
  .status-cell { padding: 10px 12px; vertical-align: top; white-space: nowrap; }
  .result-cell { padding: 10px 12px; vertical-align: top; color: #444; min-width: 100px; }
  .details-cell { padding: 10px 12px; vertical-align: top; color: #333; word-break: break-word; max-width: 420px; }
  .rem-cell { padding: 10px 12px; vertical-align: top; color: #6c4a00; font-style: italic; word-break: break-word; max-width: 300px; }
  .rem-empty { color: #bbb; font-style: normal; }

  .row-pass { background: #f8fffe; }
  .row-fail { background: #fff5f5; }
  .row-warn { background: #fffdf0; }
  .row-info { background: #fafafa; }

  .badge { display: inline-block; border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; letter-spacing: .4px; }
  .badge-pass { background: #d4edda; color: #155724; }
  .badge-fail { background: #f8d7da; color: #721c24; }
  .badge-warn { background: #fff3cd; color: #856404; }
  .badge-info { background: #e2e3e5; color: #383d41; }

  .log-box { background: #0d1117; border-radius: 10px; padding: 16px 18px; overflow-x: auto; max-height: 420px; overflow-y: auto; box-shadow: 0 1px 4px rgba(0,0,0,.15); }
  .log-line { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11.5px; line-height: 1.65; white-space: pre-wrap; word-break: break-all; }
  .log-pass  { color: #3fb950; }
  .log-fail  { color: #f85149; }
  .log-warn  { color: #d29922; }
  .log-debug { color: #6e7681; }
  .log-info  { color: #c9d1d9; }

  .footer { text-align: center; padding: 20px; font-size: 11px; color: #aaa; }

  details > summary { cursor: pointer; user-select: none; padding: 10px 0; font-weight: 600; color: #555; list-style: none; }
  details > summary::before { content: '+ '; font-size: 10px; }
  details[open] > summary::before { content: '- '; }
</style>
</head>
<body>

<div class="page-header">
  <h1>&#128274; Autopilot TPM Attestation Report</h1>
  <div class="meta">Generated: $GeneratedAt &nbsp;|&nbsp; Autopilot TPM Attestation VibeTool v0.24</div>
</div>

<div class="summary-bar">
  <div class="summary-emoji">$badgeEmoji</div>
  <div class="summary-text">$summaryText</div>
  <div class="summary-chips">
    <span class="chip chip-pass">&#9989; $passCount passed</span>
    <span class="chip chip-warn">&#9888; $warnCount warning</span>
    <span class="chip chip-fail">&#10060; $failCount failed</span>
    <span class="chip chip-info">&#8505; $infoCount info</span>
  </div>
</div>

<div class="section">
  <div class="section-title">Check results</div>
  <table>
    <thead>
      <tr>
        <th style="width:120px">Category</th>
        <th style="width:190px">Check</th>
        <th style="width:72px">Status</th>
        <th style="width:130px">Result</th>
        <th>Details</th>
        <th style="width:280px">Remediation</th>
      </tr>
    </thead>
    <tbody>
$($rowsHtml.ToString())
    </tbody>
  </table>
</div>

<div class="section">
  <details>
    <summary class="section-title">Full diagnostic log ($($LogLines.Count) lines)</summary>
    <div class="log-box" style="margin-top:10px">
$($logHtml.ToString())
    </div>
  </details>
</div>

<div class="footer">Autopilot TPM Attestation VibeTool v0.24 &mdash; call4cloud.nl</div>
</body>
</html>
"@
    return $html
}

function Export-HtmlReport {
    try {
        if ($script:Results.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show('No results to export. Run checks first.', 'Nothing to export', 'OK', 'Information') | Out-Null
            return
        }

        $folder = Join-Path $env:TEMP 'AutopilotTpmAttestationTool'
        if (-not (Test-Path $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }

        $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
        $htmlPath = Join-Path $folder "TPM_Attestation_Report_$stamp.html"
        $csvPath  = Join-Path $folder "TPM_Attestation_Results_$stamp.csv"
        $logPath  = Join-Path $folder "TPM_Attestation_Log_$stamp.txt"

        $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $html = New-HtmlReport -Results $script:Results -LogLines $script:LogLines -GeneratedAt $generatedAt
        [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.Encoding]::UTF8)

        # Also export CSV and log as companion files
        $script:Results  | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $script:LogLines | Set-Content -Path $logPath -Encoding UTF8

        # Open the HTML report in the default browser
        Start-Process $htmlPath
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error') | Out-Null
    }
}

function Export-LogAndResults {
    Export-HtmlReport
}

function New-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Autopilot TPM Attestation Tool'
    $form.ClientSize = New-Object System.Drawing.Size(1240, 800)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object System.Drawing.Size(1080, 700)
    $form.BackColor = [System.Drawing.Color]::White
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

    $main = New-Object System.Windows.Forms.TableLayoutPanel
    $main.Dock = 'Fill'
    $main.ColumnCount = 1
    $main.RowCount = 5
    $main.BackColor = [System.Drawing.Color]::White
    $main.Padding = New-Object System.Windows.Forms.Padding(0)
    $main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 104)) | Out-Null
    $main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 54)) | Out-Null
    $main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 58)) | Out-Null
    $main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Absolute), 52)) | Out-Null
    $main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle -ArgumentList ([System.Windows.Forms.SizeType]::Percent), 100)) | Out-Null
    $form.Controls.Add($main)

    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = 'Fill'
    $header.BackColor = [System.Drawing.Color]::FromArgb(245, 248, 252)
    $main.Controls.Add($header, 0, 0)

    $title = New-Object System.Windows.Forms.Label
    $title.Text = 'Autopilot TPM Attestation Tool'
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
    $title.AutoSize = $false
    $title.Location = New-Object System.Drawing.Point(18, 14)
    $title.Size = New-Object System.Drawing.Size(780, 34)
    $header.Controls.Add($title)

    $subtitle = New-Object System.Windows.Forms.Label
    $subtitle.Text = 'Checks TPM readiness, EK certificates, AIK enrollment, firmware, and required connectivity. The attestation button kicks the local TPM maintenance, EK retrieval, and AIK flow, then validates the result.'
    $subtitle.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $subtitle.AutoSize = $false
    $subtitle.Location = New-Object System.Drawing.Point(20, 54)
    $subtitle.Size = New-Object System.Drawing.Size(1120, 34)
    $subtitle.ForeColor = [System.Drawing.Color]::DimGray
    $header.Controls.Add($subtitle)

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.Dock = 'Fill'
    $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 8)
    $buttonPanel.BackColor = [System.Drawing.Color]::White
    $buttonPanel.WrapContents = $false
    $buttonPanel.AutoScroll = $true
    $main.Controls.Add($buttonPanel, 0, 1)

    $script:RunButton = New-Object System.Windows.Forms.Button
    $script:RunButton.Text = 'Run checks'
    $script:RunButton.Width = 120
    $script:RunButton.Height = 30
    $script:RunButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $buttonPanel.Controls.Add($script:RunButton)

    $script:RepairButton = New-Object System.Windows.Forms.Button
    $script:RepairButton.Text = 'Kickstart TPM attestation'
    $script:RepairButton.Width = 190
    $script:RepairButton.Height = 30
    $buttonPanel.Controls.Add($script:RepairButton)

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.SetToolTip($script:RepairButton, 'Starts TPM maintenance, EK certificate retrieval, AIK enrollment, then runs the certreq test AIK validation. It does not clear the TPM.')

    $script:CertButton = New-Object System.Windows.Forms.Button
    $script:CertButton.Text = 'Get EK certs'
    $script:CertButton.Width = 120
    $script:CertButton.Height = 30
    $buttonPanel.Controls.Add($script:CertButton)
    $toolTip.SetToolTip($script:CertButton, 'Shows ManufacturerCertificates and AdditionalCertificates returned by Get-TpmEndorsementKeyInfo.')

    $script:AikButton = New-Object System.Windows.Forms.Button
    $script:AikButton.Text = 'Test AIK cert'
    $script:AikButton.Width = 120
    $script:AikButton.Height = 30
    $buttonPanel.Controls.Add($script:AikButton)
    $toolTip.SetToolTip($script:AikButton, 'Runs the Command Prompt based AIK test using the quiet variant: cmd.exe /d /c certreq -q -enrollaik -config "". This is the same AIK test as certreq -enrollaik -config "", but avoids the CertReq popup where possible.')

    $script:ExportButton = New-Object System.Windows.Forms.Button
    $script:ExportButton.Text = 'Export report'
    $script:ExportButton.Width = 120
    $script:ExportButton.Height = 30
    $buttonPanel.Controls.Add($script:ExportButton)
    $toolTip.SetToolTip($script:ExportButton, 'Generates a self-contained HTML report and opens it in your default browser. Also saves a CSV and log file alongside it.')

    $script:ExportTpmLogsButton = New-Object System.Windows.Forms.Button
    $script:ExportTpmLogsButton.Text = 'Export TPM logs'
    $script:ExportTpmLogsButton.Width = 135
    $script:ExportTpmLogsButton.Height = 30
    $buttonPanel.Controls.Add($script:ExportTpmLogsButton)
    $toolTip.SetToolTip($script:ExportTpmLogsButton, 'Exports TPM related EVTX logs, TPM tool output, registry context, and opens the export folder.')

    $script:ClearButton = New-Object System.Windows.Forms.Button
    $script:ClearButton.Text = 'Clear'
    $script:ClearButton.Width = 90
    $script:ClearButton.Height = 30
    $buttonPanel.Controls.Add($script:ClearButton)

    $script:WinUpdateButton = New-Object System.Windows.Forms.Button
    $script:WinUpdateButton.Text = 'Check WU'
    $script:WinUpdateButton.Width = 100
    $script:WinUpdateButton.Height = 30
    $buttonPanel.Controls.Add($script:WinUpdateButton)
    $toolTip.SetToolTip($script:WinUpdateButton, 'Scans for pending Windows 10/11 cumulative updates using the Windows Update COM API. Missing TPM-related fixes are a common attestation blocker. This runs on demand and is not part of the main Run checks flow.')

    # ---------------------------------------------------------------
    # Inline progress panel (row 2) - hidden until a check runs
    # ---------------------------------------------------------------
    $script:ProgressPanel = New-Object System.Windows.Forms.Panel
    $script:ProgressPanel.Dock = 'Fill'
    $script:ProgressPanel.BackColor = [System.Drawing.Color]::FromArgb(240, 244, 250)
    $script:ProgressPanel.Padding = New-Object System.Windows.Forms.Padding(14, 6, 14, 6)
    $script:ProgressPanel.Visible = $false
    $main.Controls.Add($script:ProgressPanel, 0, 2)

    $script:ProgressLabel = New-Object System.Windows.Forms.Label
    $script:ProgressLabel.AutoSize = $false
    $script:ProgressLabel.Location = New-Object System.Drawing.Point(14, 4)
    $script:ProgressLabel.Size = New-Object System.Drawing.Size(1100, 18)
    $script:ProgressLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $script:ProgressLabel.ForeColor = [System.Drawing.Color]::FromArgb(30, 80, 160)
    $script:ProgressLabel.Text = ''
    $script:ProgressPanel.Controls.Add($script:ProgressLabel)

    $script:ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $script:ProgressBar.Location = New-Object System.Drawing.Point(14, 26)
    $script:ProgressBar.Size = New-Object System.Drawing.Size(1100, 14)
    $script:ProgressBar.Minimum = 0
    $script:ProgressBar.Maximum = 1
    $script:ProgressBar.Value = 0
    $script:ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $script:ProgressPanel.Controls.Add($script:ProgressBar)

    $script:ProgressDetailLabel = New-Object System.Windows.Forms.Label
    $script:ProgressDetailLabel.AutoSize = $false
    $script:ProgressDetailLabel.Location = New-Object System.Drawing.Point(14, 43)
    $script:ProgressDetailLabel.Size = New-Object System.Drawing.Size(1100, 14)
    $script:ProgressDetailLabel.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $script:ProgressDetailLabel.ForeColor = [System.Drawing.Color]::DimGray
    $script:ProgressDetailLabel.Text = ''
    $script:ProgressPanel.Controls.Add($script:ProgressDetailLabel)

    $script:SummaryLabel = New-Object System.Windows.Forms.Label
    $script:SummaryLabel.Dock = 'Fill'
    $script:SummaryLabel.TextAlign = 'MiddleLeft'
    $script:SummaryLabel.Padding = New-Object System.Windows.Forms.Padding(18, 0, 0, 0)
    $script:SummaryLabel.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $main.Controls.Add($script:SummaryLabel, 0, 3)
    Set-Summary -Text 'Ready to run checks.' -State 'IDLE'

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.Orientation = 'Horizontal'
    $split.SplitterDistance = 430
    $split.Panel1MinSize = 220
    $split.Panel2MinSize = 120
    $split.BackColor = [System.Drawing.Color]::White
    $main.Controls.Add($split, 0, 4)

    $script:Grid = New-Object System.Windows.Forms.DataGridView
    $script:Grid.Dock = 'Fill'
    $script:Grid.AllowUserToAddRows = $false
    $script:Grid.AllowUserToDeleteRows = $false
    $script:Grid.ReadOnly = $true
    $script:Grid.SelectionMode = 'FullRowSelect'
    $script:Grid.MultiSelect = $false
    $script:Grid.RowHeadersVisible = $false
    $script:Grid.AutoSizeColumnsMode = 'None'
    $script:Grid.AutoSizeRowsMode = 'None'
    $script:Grid.ScrollBars = 'Both'
    $script:Grid.BackgroundColor = [System.Drawing.Color]::White
    $script:Grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $script:Grid.ColumnHeadersHeight = 30
    $script:Grid.RowTemplate.Height = 24
    $script:Grid.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $script:Grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::False
    $script:Grid.ColumnHeadersDefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::False
    $script:Grid.Columns.Add('Category', 'Category') | Out-Null
    $script:Grid.Columns.Add('Check', 'Check') | Out-Null
    $script:Grid.Columns.Add('Status', 'Status') | Out-Null
    $script:Grid.Columns.Add('Result', 'Result') | Out-Null
    $script:Grid.Columns.Add('Details', 'Details') | Out-Null
    $script:Grid.Columns.Add('Remediation', 'Remediation') | Out-Null
    $script:Grid.Columns['Category'].Width = 150
    $script:Grid.Columns['Check'].Width = 240
    $script:Grid.Columns['Status'].Width = 80
    $script:Grid.Columns['Result'].Width = 160
    $script:Grid.Columns['Details'].Width = 430
    $script:Grid.Columns['Remediation'].Width = 430
    $script:Grid.Columns['Status'].DefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $script:Grid.Columns['Result'].DefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $split.Panel1.Controls.Add($script:Grid)

    $script:LogBox = New-Object System.Windows.Forms.RichTextBox
    $script:LogBox.Dock = 'Fill'
    $script:LogBox.ReadOnly = $true
    $script:LogBox.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
    $split.Panel2.Controls.Add($script:LogBox)

    $script:RunButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        $script:WinUpdateButton.Enabled = $false
        try {
            Invoke-AllChecks
        }
        finally {
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
            $script:WinUpdateButton.Enabled = $true
        }
    })

    $script:RepairButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        try {
            Invoke-TpmAttestationAction
        }
        finally {
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
        }
    })

    $script:CertButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        try {
            Show-TpmEndorsementCertificates
        }
        finally {
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
        }
    })

    $script:AikButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        try {
            Start-ProgressWindow -Title 'AIK certificate test' -Maximum 5 -Message 'Starting AIK certreq test...'
            Test-AikTestCertificate -ShowPopup
            Close-ProgressWindow
            Update-FinalSummary
        }
        finally {
            Close-ProgressWindow
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
        }
    })

    $script:ExportButton.Add_Click({ Export-LogAndResults })
    $script:ExportTpmLogsButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        try {
            Export-TpmEventLogs
        }
        finally {
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
        }
    })
    $script:ClearButton.Add_Click({ Reset-Results; Set-Summary -Text 'Ready to run checks.' -State 'IDLE' })

    $script:WinUpdateButton.Add_Click({
        $script:RunButton.Enabled = $false
        $script:RepairButton.Enabled = $false
        $script:ExportTpmLogsButton.Enabled = $false
        $script:CertButton.Enabled = $false
        $script:AikButton.Enabled = $false
        $script:WinUpdateButton.Enabled = $false
        try {
            Invoke-WindowsUpdateCheck
        }
        finally {
            $script:RunButton.Enabled = $true
            $script:RepairButton.Enabled = $true
            $script:ExportTpmLogsButton.Enabled = $true
            $script:CertButton.Enabled = $true
            $script:AikButton.Enabled = $true
            $script:WinUpdateButton.Enabled = $true
        }
    })

    # Build the spinner overlay last so it sits on top of everything
    New-SpinnerOverlay -ParentForm $form | Out-Null

    return $form
}

$form = New-MainForm
[void]$form.ShowDialog()
