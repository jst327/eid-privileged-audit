# Microsoft 365 Privileged Audit

## Overview

Building on the concept of Mark Ziesemer's <a href="https://github.com/ziesemer/ad-privileged-audit" target="_blank">AD Privileged Audit</a>, this project delivers a PowerShell script designed to generate security-focused [reports](#reports) for your Microsoft 365 tenant. The reports provide valuable insights to enhance security and ensure compliance across your environment. By leveraging the Microsoft Graph API and PowerShell modules, the script efficiently generates detailed reports, typically presented in an interactive [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-7.4) interface within minutes.

## Features

* **User registration details:** Report on users registration details including MFA, Passwordless, and SSPR.
* **Privileged users:** Report on users with Entra roles whether they are assigned or eligible.
* **Privileged groups:** Report on Entra roles and counts of how many users are assigned or eligible.
* **Stale users:** Report on users that have not signed in for 30 days.
* **Stale passwords:** Report on users with passwords that have not been updated in a year.
* **User licenses:** Report on licenses assigned to users.
* **Tenant licenses:** Report on licenses and how many are total, in use, and available.
* **Tenant auditing:** Reports on whether auditing has been enabled in the tenant.
* **Shared mailbox sign-in allowed:** Reports on shared maillboxes that have sign-in enabled.

## Prerequisites
1. **PowerShell Version:** PowerShell 5.1 requiredDesigned to be fast and efficient, typically provides "immediate" (no post-processing required) results within several minutes.
2. **PowerShell Modules:** While the script checks, it will not install the following required modules:
   * Microsoft.Graph
   * ExchangeOnlineManagement (for auditing check)
3. **Permissions:** The account running the script should have one of the following Entra roles:
   * Global Administrator
   * Application Administrator
   * Cloud Application Administrator

## Execution
1. Right-click **[here](m365-privileged-audit.ps1?raw=1)**, then click "Save link as" from your web browser.
   1. Save to your Downloads, Desktop, or another convenient location.
2. Right-click the script from your desktop (or location you chose), then click "Properties".
   1. Under security, you may need to check the "Unblock" checkbox, then click "OK".
3. Right-click the script again, then click "Run with PowerShell".
4. Reports will be provided directly to the screen (using PowerShell's [Out-GridView](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-gridview?view=powershell-7.4)).
5. The displayed grids can be minimized or closed one-at-a-time as they are reviewed. Completing the "Press any key to continue..." prompt in or closing the main PowerShell window will close any remaining windows.

## Reports
Current reports include:
1. User Registration Details
   1. Much like the user registration details that can be exported from Entra. It will include columns like:
      * Is Admin?
      * Is MFA Capable?
      * Is MFA Registered?
      * Is Passwordless Capable?
      * Is SSPR Capable?
      * Is SSPR Enabled?
      * Is SSPR Registered?
2. Privileged Users
   1. Any assigned or eligible user with an Entra role will show up in this report. It will include columns like:
      * Role Name
      * Role Type
      * Directory Scope (Administrative Unit)
      * Is Guest?
      * Is Activated? (For PIM)
      * Created Date (UTC) (When the role was assigned or made eligible)
      * Expiration Type
      * Expiration Date (UTC)
3. Privileged Groups
   1. A count of all assigned or eligible Entra roles "groups" in this report.
4. Stale Users
   1. Users that haven't signed into your tenant in over 30 days will show up in this report. It will include columns like:
      * Display Name
      * User Principal Name
      * Created Date Time
      * Last Successful Sign In Date
      * Days Since Last Sign In
      * Account Enabled
      * Is Licensed
      * User Type
5. Stale Passwords
   1. Users that haven't changed their password in over a year will show up in this report. If no user has a stale password, this report will not show. An informational message will be included in the PowerShell window stating "No stale passwords found.".
6. User Licenses
   1. A minimal report reflecting all users and their assigned licenses. Useful when comparing to privileged and stale users' reports.
7. Tenant Licenses
   1. This report shows all licenses in your tenant including how many total, in use, and available quantities there are.
8. Shared Mailbox Sign-In Allowed
   1. Any shared mailbox that has sign-in enabled for their user will show up here.
   2. See [https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide) for more information about shared mailboxes.
9. Warnings and Errors
    1. Any warnings or errors will report here.
    2. Examples of warnings that may show up are:
       * Stale users found.
       * Stale passwords found.
       * Auditing is not enabled for your tenant.
       * The shared mailbox account for `user@contoso.com` is enabled.

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
