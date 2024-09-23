
# Domain Admin Audit Scripts

This repository contains two PowerShell scripts designed to audit **Domain Admin** accounts in an Active Directory environment. These scripts provide detailed information about the **Domain Admins** group, including their last logon times, and for the second script, logon durations based on Windows Security Event logs.

## Scripts

1. **DA_Audit.ps1**: 
   - Retrieves the list of **Domain Admin** accounts and their last logon times.
   - Exports the results to a CSV file.

2. **DA_Audit-Durations.ps1**:
   - In addition to retrieving last logon times, this script calculates **logon durations** for **Domain Admin** accounts by parsing the Windows Security Event logs on specified domain controllers or servers.
   - Exports the results, including logon durations, to a CSV file.

---

## Prerequisites

- **Operating System**: 
  - Windows 10 or later.
  - Windows Server 2012 or later.
  
- **PowerShell**:
  - Version 5.1 or higher.

- **Active Directory Module**:
  - The scripts automatically check and attempt to install the **Active Directory PowerShell module** if it is not already present.

- **Permissions**:
  - **Administrative Privileges**: Required to install the Active Directory module and to access event logs for logon duration calculation.
  - **Active Directory Access**: Read access to the **Domain Admins** group and user properties.
  - **File System Access**: Write permissions to the export directory.

- **Event Log Access** (For `DA_Audit-Durations.ps1`):
  - The user running the script must have permissions to read Security Event Logs on the specified domain controllers or member servers.

---

## Script: DA_Audit.ps1

### Overview

The `DA_Audit.ps1` script collects information about Domain Admin accounts and their last logon times. This information is essential for auditing purposes, ensuring compliance with security policies, and monitoring the activity of privileged accounts.

### Features

- **Automatic Active Directory Module Installation**: 
  - The script checks for the Active Directory module and installs it if not present.
  
- **Data Collection**: 
  - Retrieves all members of the **Domain Admins** group.
  - Fetches their `SamAccountName`, `LastLogonDate`, and `Enabled` status.
  
- **Export to CSV**: 
  - Outputs the results to a CSV file for further analysis.

### Usage

1. **Download the Script**: 
   - Save `DA_Audit.ps1` to a location on your machine.

2. **Run PowerShell as Administrator**:
   - Right-click the PowerShell icon and select **"Run as Administrator"**.

3. **Execute the Script**:

   ```powershell
   .\DA_Audit.ps1
   ```

4. **Review the Output**:
   - The total number of Domain Admin accounts and their last logon times will be displayed in the console.
   - A CSV file will be created at `C:\Reports\DomainAdminsLogonTimes.csv`.

---

## Script: DA_Audit-Durations.ps1

### Overview

The `DA_Audit-Durations.ps1` script builds on `DA_Audit.ps1` by calculating **logon durations** for each Domain Admin account. It parses the Windows Security Event logs to match logon and logoff events and determine the time each user was logged in.

### Features

- **Logon Duration Calculation**:
  - Retrieves and pairs logon and logoff events from the Security Event Logs to calculate logon durations.
  
- **Export to CSV**:
  - Outputs the results, including total logon durations, to a CSV file.

### Usage

1. **Download the Script**: 
   - Save `DA_Audit-Durations.ps1` to a location on your machine.

2. **Update the Script Parameters**:
   - **Date Range**: Modify the `$StartDate` and `$EndDate` variables to match the period you're analyzing.
   - **Domain Controllers/Servers**: Replace `@("DC1", "DC2")` in the `$ComputerNames` array with the actual names of your domain controllers or relevant servers.

3. **Run PowerShell as Administrator**:
   - Right-click the PowerShell icon and select **"Run as Administrator"**.

4. **Execute the Script**:

   ```powershell
   .\DA_Audit-Durations.ps1
   ```

5. **Review the Output**:
   - The script will display the total number of Domain Admin accounts, their last logon times, and their logon durations (in hours).
   - A CSV file will be created at `C:\Reports\DomainAdminsLogonDurations.csv`.

---

## Output Details

### CSV Files

- **DA_Audit.ps1**:
  - Default location: `C:\Reports\DomainAdminsLogonTimes.csv`
  - Columns:
    - `Name`
    - `SamAccountName`
    - `LastLogonDate`

- **DA_Audit-Durations.ps1**:
  - Default location: `C:\Reports\DomainAdminsLogonDurations.csv`
  - Columns:
    - `Name`
    - `SamAccountName`
    - `LastLogonDate`
    - `TotalDuration` (Hours)

---

## Troubleshooting

### Active Directory Module Installation Fails

- **Symptom**: 
  - Error indicating failure to install the Active Directory module.
  
- **Solution**: 
  - Ensure PowerShell is running with administrative privileges.
  - Verify that the system has access to the internet for installing the required module.
  - Manually install the **Active Directory module** if needed.

### Access Denied Errors

- **Symptom**: 
  - Errors related to accessing Active Directory objects or Security Event Logs.
  
- **Solution**: 
  - Ensure that you are running the script with an account that has the necessary administrative privileges.

### No Logon Duration Data (For DA_Audit-Durations.ps1)

- **Symptom**: 
  - Logon durations are missing or zero.
  
- **Solution**: 
  - Verify the date range and domain controller names in the script.
  - Check that the Security Event Logs on the target computers contain the necessary logon and logoff events.

---

## Security Considerations

- **Sensitive Data**: 
  - Handle the output files securely as they contain sensitive account information. Share the results only with authorized personnel.
  
- **Permissions**:
  - Both scripts require elevated permissions to access Active Directory objects and Event Logs. Ensure compliance with your organization's security policies.

---

## License

This repository is licensed under the MIT License. You are free to use, modify, and distribute these scripts under the terms of the license.

---

## Contact

For any issues, questions, or feature requests, feel free to open an issue or contact the repository maintainers.
