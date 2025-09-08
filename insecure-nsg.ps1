# <summary>
# Script: nsg.ps1
# Description: This script analyzes all Azure Network Security Groups (NSGs) in the current subscription and identifies inbound rules that allow traffic from the Internet (i.e., source is '*' or 'Internet').
# For each insecure rule found, it outputs a table with details and a link to Azure network security best practices.
#
# Usage:
#   - Ensure you have the Az PowerShell module installed and are authenticated to Azure.
#   - Run the script in a PowerShell session with appropriate permissions.
#
# Output:
#   - A table listing NSG name, location, rule name, priority, protocol, port range, source/destination addresses, and a best practices link for each insecure rule.
#   - If no insecure rules are found, a message is displayed.
#
# Reference:
#   https://learn.microsoft.com/en-us/azure/virtual-network/network-security-best-practices
#
# Ensure Az module is installed
Import-Module Az.Network


# Authenticate to Azure only if not already authenticated
if (-not (Get-AzContext)) {
    Connect-AzAccount
}



# Fetch all Network Security Groups

$nsgs = Get-AzNetworkSecurityGroup
# Initialize results array
$results = @()

# Analyze each NSG's security rules
foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules) {
        $source = $rule.SourceAddressPrefix
        $direction = $rule.Direction
        $access = $rule.Access

        # Determine if rule is insecure
        $isInsecure = ($direction -eq "Inbound" -and $access -eq "Allow" -and ($source -eq "*" -or $source -eq "Internet"))
        if ($isInsecure) {
            $isSecure = '❌'
        } else {
            $isSecure = '✅'
        }

        $result = [PSCustomObject]@{
            IsSecure = $isSecure
            NSGName = $nsg.Name
            Location = $nsg.Location
            RuleName = $rule.Name
            Priority = $rule.Priority
            Protocol = $rule.Protocol
            PortRange = $rule.DestinationPortRange
            SourceAddress = $source
            DestinationAddress = $rule.DestinationAddressPrefix
            BestPractices = 'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-best-practices'
        }
        $results += $result

        # Collect insecure rules for deletion
        if ($isInsecure) {
            if (-not $global:InsecureRulesToDelete) { $global:InsecureRulesToDelete = @() }
            $global:InsecureRulesToDelete += [PSCustomObject]@{
                NSGName = $nsg.Name
                RuleName = $rule.Name
                ResourceGroupName = $nsg.ResourceGroupName
            }
        }
    }
}

# Output all rules as a table
$results | Format-Table -AutoSize

# Prompt to delete insecure rules if any found
if ($global:InsecureRulesToDelete -and $global:InsecureRulesToDelete.Count -gt 0) {
    Write-Host "\nThe following insecure rules can be deleted:" -ForegroundColor Yellow
    $global:InsecureRulesToDelete | Format-Table NSGName,RuleName,ResourceGroupName
    $confirm = Read-Host "\nDo you want to delete ALL these insecure rules? Type 'yes' to confirm"
    if ($confirm -eq 'yes') {
        foreach ($item in $global:InsecureRulesToDelete) {
            Write-Host "Deleting rule $($item.RuleName) from NSG $($item.NSGName)..." -ForegroundColor Red
            Remove-AzNetworkSecurityRuleConfig -Name $item.RuleName -NetworkSecurityGroupName $item.NSGName -ResourceGroupName $item.ResourceGroupName -Force
        }
        Write-Host "All insecure rules deleted." -ForegroundColor Green
    } else {
        Write-Host "No rules were deleted." -ForegroundColor Cyan
    }
} else {
    Write-Host "No insecure rules detected. ✅ All is OK!" -ForegroundColor Green
}
