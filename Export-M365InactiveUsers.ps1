function Get-InactiveUsers {
    # Initialize a List to store the data
    $Report = [System.Collections.Generic.List[Object]]::new()

    # Connect to Microsoft Graph API
    Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

    # Get properties
    $Properties = @(
        'Id',
        'DisplayName',
        'Mail',
        'UserPrincipalName',
        'UserType',
        'AccountEnabled',
        'SignInActivity',
        'CreatedDateTime',
        'AssignedLicenses'
    )

    # Get all users along with the properties
    $AllUsers = Get-MgUser -All -Property $Properties | Select-Object $Properties

    foreach ($User in $AllUsers) {
        $LastSuccessfulSignInDate = if ($User.SignInActivity.LastSuccessfulSignInDateTime) {
            $User.SignInActivity.LastSuccessfulSignInDateTime
        }
        else {
            "Never Signed-in."
        }

        $DaysSinceLastSignIn = if ($User.SignInActivity.LastSuccessfulSignInDateTime) {
            (New-TimeSpan -Start $User.SignInActivity.LastSuccessfulSignInDateTime -End (Get-Date)).Days
        }
        else {
            "N/A"
        }

        # Check if the user is licensed
        $IsLicensed = if ($User.AssignedLicenses) {
            "Yes"
        }
        else {
            "No"
        }

        # Collect data
        if (!$User.SignInActivity.LastSuccessfulSignInDateTime -or (Get-Date $User.SignInActivity.LastSuccessfulSignInDateTime)) {
            $ReportLine = [PSCustomObject]@{
                Id                       = $User.Id
                UserPrincipalName        = $User.UserPrincipalName
                DisplayName              = $User.DisplayName
                Email                    = $User.Mail
                UserType                 = $User.UserType
                AccountEnabled           = $User.AccountEnabled
                LastSuccessfulSignInDate = $LastSuccessfulSignInDate
                DaysSinceLastSignIn      = $DaysSinceLastSignIn
                CreatedDateTime          = $User.CreatedDateTime
                IsLicensed               = $IsLicensed
            }
            # Add the report line to the List
            $Report.Add($ReportLine)
        }
    } 

    # Sort the entire collection by 'Assigned Role'
    $InactiveUsers = $InactiveUsers | Sort-Object 'DaysSinceLastSignInAssigned'
}

# Display data using Out-GridView
$InactiveUsers = Get-InactiveUsers
$InactiveUsers | Out-GridView -Title "Inactive Users"