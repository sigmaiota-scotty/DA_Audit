<#
.SYNOPSIS
    Retrieves the total number of Domain Admin accounts and their last logon times.

.DESCRIPTION
    This script checks for the Active Directory module and attempts to install it if not present.
    It then retrieves the total number of Domain Admin accounts and their last logon times.
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

    # Optional: Export the results to a CSV file
    $exportFolder = "C:\Reports"
    $exportPath = Join-Path -Path $exportFolder -ChildPath "DomainAdminsLogonTimes.csv"

    # Ensure the export directory exists
    if (-not (Test-Path -Path $exportFolder)) {
        New-Item -Path $exportFolder -ItemType Directory -Force
    }

    $adminDetails | Export-Csv -Path $exportPath -NoTypeInformation

    Write-Host "`nThe admin account details have been exported to $exportPath"
}
catch {
    Write-Error "An unexpected error occurred: $_. Exception.Message"
    Write-Error "Please contact IS Support for assistance."
    exit 1
}

