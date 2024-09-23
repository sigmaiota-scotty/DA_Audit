<#
.SYNOPSIS
    Retrieves the total number of Domain Admin accounts, their last logon times, and logon durations.

.DESCRIPTION
    This script checks for the Active Directory module and attempts to install it if not present.
    It then retrieves the total number of Domain Admin accounts, their last logon times,
    and calculates logon durations by parsing Security Event Logs on specified servers.
    If it cannot install the module due to insufficient privileges, it suggests contacting IS Support.

.NOTES
    Author: Scott Isaac
    Date:   23 Sep 2024

#>

# Function to check and install the Active Directory module
function Ensure-ActiveDirectoryModule {
    # Check if the Active Directory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "Active Directory module not found. Attempting to install..."

        # Determine the OS version
        $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
        $osBuild = [System.Version]$osVersion

        try {
            if ($osBuild.Major -ge 10) {
                # For Windows 10 and Windows Server 2016 or later
                Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
                Write-Host "Active Directory module installed successfully."
            }
            else {
                # For earlier versions, attempt to install RSAT via Windows Update
                Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop
                Write-Host "Active Directory module installed successfully."
            }
        }
        catch {
            Write-Error "Unable to install the Active Directory module. Please run this script as an administrator or contact IS Support."
            exit 1
        }
    }
    else {
        Write-Host "Active Directory module is already installed."
    }

    # Import the Active Directory module
    Import-Module ActiveDirectory -ErrorAction Stop
}

# Function to calculate logon durations from event logs
function Get-LogonDurations {
    param (
        [string[]]$ComputerNames,
        [string[]]$UserSamAccounts,
        [DateTime]$StartDate,
        [DateTime]$EndDate
    )

    # Array to hold logon duration data
    $logonData = @()

    # Define event IDs for logon and logoff
    $logonEventID = 4624  # An account was successfully logged on
    $logoffEventID = 4634 # An account was logged off
    $disconnectEventID = 4647 # User initiated logoff

    foreach ($computer in $ComputerNames) {
        Write-Host "Processing event logs on computer: $computer"

        try {
            # Get logon and logoff events for the specified users within the date range
            $events = Get-WinEvent -ComputerName $computer -FilterHashtable @{
                LogName = 'Security'
                StartTime = $StartDate
                EndTime = $EndDate
                ID = @($logonEventID, $logoffEventID, $disconnectEventID)
            } -ErrorAction Stop

            # Filter events for the specified users
            $userEvents = $events | Where-Object {
                $_.Properties[1].Value -in $UserSamAccounts
            }

            # Group events by user
            foreach ($user in $UserSamAccounts) {
                $userLogonEvents = $userEvents | Where-Object {
                    $_.Properties[1].Value -eq $user -and $_.Id -eq $logonEventID
                } | Sort-Object TimeCreated

                $userLogoffEvents = $userEvents | Where-Object {
                    $_.Properties[1].Value -eq $user -and ($_.Id -eq $logoffEventID -or $_.Id -eq $disconnectEventID)
                } | Sort-Object TimeCreated

                # Pair logon and logoff events to calculate durations
                for ($i = 0; $i -lt $userLogonEvents.Count; $i++) {
                    $logonTime = $userLogonEvents[$i].TimeCreated

                    # Find the next logoff event after the logon event
                    $logoffTime = $userLogoffEvents | Where-Object {
                        $_.TimeCreated -gt $logonTime
                    } | Select-Object -First 1 -Property TimeCreated

                    if ($logoffTime) {
                        $duration = $logoffTime.TimeCreated - $logonTime
                    }
                    else {
                        # If no logoff event found, assume session is still active or logoff event is missing
                        $duration = $EndDate - $logonTime
                    }

                    # Add data to the array
                    $logonData += [PSCustomObject]@{
                        ComputerName   = $computer
                        User           = $user
                        LogonTime      = $logonTime
                        LogoffTime     = $logoffTime.TimeCreated
                        Duration       = $duration
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to retrieve events from $computer: $_"
        }
    }

    return $logonData
}

# Main script execution
try {
    # Ensure the Active Directory module is available
    Ensure-ActiveDirectoryModule

    # Get the members of the Domain Admins group recursively
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive

    if ($domainAdmins.Count -eq 0) {
        Write-Host "No members found in the Domain Admins group."
        exit 0
    }

    # Display the total number of domain admin accounts
    $totalAdmins = $domainAdmins.Count
    Write-Host "`nTotal Domain Admin Accounts: $totalAdmins`n"

    # Prepare a list to store admin account details
    $adminDetails = @()

    # List to collect SamAccountNames of admins
    $adminSamAccounts = @()

    # Loop through each admin account to get last logon information
    foreach ($admin in $domainAdmins) {
        # Get AD user properties, including LastLogonDate and Enabled status
        $user = Get-ADUser -Identity $admin.SamAccountName -Properties LastLogonDate, Enabled -ErrorAction SilentlyContinue

        if ($null -eq $user) {
            Write-Warning "User account '$($admin.SamAccountName)' not found or inaccessible."
            continue
        }

        # Skip if the account is disabled (optional)
        if ($user.Enabled -eq $false) {
            continue
        }

        # Add SamAccountName to the list
        $adminSamAccounts += $user.SamAccountName

        # Create a custom object to store the details
        $adminInfo = [PSCustomObject]@{
            Name           = $user.Name
            SamAccountName = $user.SamAccountName
            LastLogonDate  = $user.LastLogonDate
        }

        # Add the admin info to the list
        $adminDetails += $adminInfo

        # Display the account name and last logon date
        Write-Host "User: $($user.SamAccountName) | Last Logon Date: $($user.LastLogonDate)"
    }

    # Specify the date range for event log analysis
    $StartDate = (Get-Date).AddDays(-7)  # Adjust the number of days as needed
    $EndDate = Get-Date

    Write-Host "`nCalculating logon durations from $StartDate to $EndDate...`n"

    # Specify the computers to query (e.g., domain controllers)
    # Modify this list based on your environment
    $ComputerNames = @("DC1", "DC2")  # Replace with your domain controllers' names

    # Get logon durations
    $logonDurations = Get-LogonDurations -ComputerNames $ComputerNames -UserSamAccounts $adminSamAccounts -StartDate $StartDate -EndDate $EndDate

    # Merge logon durations with admin details
    $adminDetailsWithDurations = foreach ($admin in $adminDetails) {
        $userDurations = $logonDurations | Where-Object { $_.User -eq $admin.SamAccountName }

        # Calculate total duration
        $totalDuration = (New-TimeSpan -Seconds 0)
        foreach ($session in $userDurations) {
            $totalDuration += $session.Duration
        }

        # Add duration to admin details
        [PSCustomObject]@{
            Name           = $admin.Name
            SamAccountName = $admin.SamAccountName
            LastLogonDate  = $admin.LastLogonDate
            TotalDuration  = [math]::Round($totalDuration.TotalHours, 2)
        }
    }

    # Display admin details with durations
    foreach ($admin in $adminDetailsWithDurations) {
        Write-Host "User: $($admin.SamAccountName) | Last Logon Date: $($admin.LastLogonDate) | Total Logon Duration (Hours): $($admin.TotalDuration)"
    }

    # Export the results to a CSV file
    $exportFolder = "C:\Reports"
    $exportPath = Join-Path -Path $exportFolder -ChildPath "DomainAdminsLogonDurations.csv"

    # Ensure the export directory exists
    if (-not (Test-Path -Path $exportFolder)) {
        New-Item -Path $exportFolder -ItemType Directory -Force
    }

    $adminDetailsWithDurations | Export-Csv -Path $exportPath -NoTypeInformation

    Write-Host "`nThe admin account details with logon durations have been exported to $exportPath"
}
catch {
    Write-Error "An unexpected error occurred: $_.Exception.Message"
    Write-Error "Please contact IS Support for assistance."
    exit 1
}

