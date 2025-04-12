# Entra ID Privileged Audit

## Overview

Building on the concept of Mark Ziesemer's [AD Privileged Audit](https://github.com/ziesemer/ad-privileged-audit), this project delivers a PowerShell script designed to generate security-focused [reports](#reports) for Entra ID. The reports provide valuable insights to enhance security and ensure compliance across your environment. By leveraging the Microsoft Graph API and PowerShell modules, the script efficiently generates detailed reports, typically presented in an interactive [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-7.4) interface within minutes.

## Features

* **Privileged users:** Reports users with Entra roles that may be assigned or eligible depending on tenant Entra ID Premium licensing.
* **Privileged roles:** Reports Entra roles and counts of how many users are assigned or eligible depending on tenant Entra ID Premium licensing.
* **Stale users:** Reports users that have not been seen in Entra for more than 30 days.
* **Stale passwords:** Reports users with passwords that have not been updated within the past 365 days.
* **Stale devices:** Reports devices that have not been see in Entra for more than 90 days.
* **Unsupported OS:** Reports devices that are running on unsupported or soon to be unsupported (<365 days) operating system.
* **User registration details:** Reports user registration details including MFA, Passwordless, and SSPR.
* **User licenses:** Reports licenses assigned to users and whether they are enabled or disabled.
* **Tenant licenses:** Reports licenses in tenant and how many are total, in use, and available.

## Prerequisites

1. **PowerShell Version:** PowerShell 5.1 required. Designed to be fast and efficient, typically provides "immediate" (no post-processing required) results within several minutes.
2. **PowerShell Modules:** While the script checks, it will not install the following required modules:
   * Microsoft.Graph
   * ExchangeOnlineManagement (for auditing check)
3. **Permissions:** The account running the script should have one of the following Entra roles:
   * Global Administrator
   * Application Administrator
   * Cloud Application Administrator

## Execution

1. Right-click **[here](eid-privileged-audit.ps1?raw=1)**, then click "Save link as" from your web browser.
   1. Save to your Downloads, Desktop, or another convenient location.
2. Right-click the script from your desktop (or location you chose), then click "Properties".
   1. Under security, you may need to check the "Unblock" checkbox, then click "OK".
3. Right-click the script again, then click "Run with PowerShell".
4. Reports will be provided directly to the screen (using PowerShell's [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview)).
5. The displayed grids can be minimized or closed one-at-a-time as they are reviewed. Completing the "Press any key to continue..." prompt in or closing the main PowerShell window will close any remaining windows.

## Reports

Current reports include:

1. Privileged Users
   1. Reports assigned or eligible role assignments. Eligible roles will only show if the tenant is detected in having Entra ID Premium 2 licensing. It will include columns like:
      * Role Id
      * Role Name
      * Member Depth (Users inheriting permissions from a group will show member depth of 2)
      * Object Id (Id of user)
      * Display Name (Of User)
      * On Premises Sync Enabled
      * Type
      * Parent Group (Group that user is a member of)
      * Created Date Time
      * Last Successful Sign In Date Time
      * Days Since Last Sign In
      * Last Password Change
      * Is Built In
      * Role Type
      * Directory Scope (Administrative Unit)
      * Is Activated
      * Created Date (UTC) (For eligible roles)
      * Expiration Type (For eligible roles)
      * Expiration Date (UTC) (For eligible roles)
      * User Principal Name
      * Role Description
2. Privileged Roles
   1. Reports all Entra roles. Listing Global Administrators first then sorted by role assignments. Users inheriting role assignments from a group will have a member depth of two.
      * Role Name
      * Is Built In
      * Assigned #
      * Eligible #
      * Description
3. Stale Users
   1. Users that haven't signed into your tenant in over 30 days will show up in this report. It will include columns like:
      * Object Id
      * Display Name
      * User Principal Name
      * Created Date Time
      * Last Successful Sign In Date
      * Days Since Last Sign In
      * Last Password Change Date Time
      * Account Enabled
      * Is Licensed
      * User Type
4. Stale Passwords
   1. Users that haven't changed their password in over a year will show up in this report. If no user has a stale password, this report will not show. An informational message will be included in the PowerShell window stating "No stale passwords found.".
5. Stale Devices
   1. Reports on devices that haven't been see within the past 90 days in your Entra tenant. (Work in Progress!)
      * Display Name
      * Device Id
      * Operating System
      * Operating System Version
      * Approximate Last Sign In Date Time
6. Unsupported Operating System (Work in Progress!)
7. User Registration Details
   1. Much like the user registration details that can be exported from Entra. It will include columns like:
      * Is Admin?
      * Is MFA Capable?
      * Is MFA Registered?
      * Is Passwordless Capable?
      * Is SSPR Capable?
      * Is SSPR Enabled?
      * Is SSPR Registered?
8. User Licenses
   1. A minimal report reflecting all users and their assigned licenses. Useful when comparing to privileged and stale users' reports.
9. Tenant Licenses
   1. This report shows all licenses in your tenant including how many total, in use, and available quantities there are.
10. Warnings and Errors
    1. Any warnings or errors will report here.
    2. Examples of warnings that may show up are:
       * Stale users found.
       * Stale passwords found.

## Roadmap

Ideas for future revisions.

  1. Risky detections report
  2. Risky users report
  3. Risky sign-ins report
  4. Enterprise App permissions
  5. SharePoint permissions

## Author

Justin Tucker

* [https://www.linkedin.com/in/-tucker/](https://www.linkedin.com/in/-tucker/)
