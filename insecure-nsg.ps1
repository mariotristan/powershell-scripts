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

        # Check if rule allows inbound traffic from Internet
        if ($direction -eq "Inbound" -and $access -eq "Allow" -and ($source -eq "*" -or $source -eq "Internet")) {
            $result = [PSCustomObject]@{
                Insecure = '❌'
                NSGName = $nsg.Name
                Location = $nsg.Location
                RuleName = $rule.Name
                Priority = $rule.Priority
                Protocol = $rule.Protocol
                PortRange = $rule.DestinationPortRange
                SourceAddress = $source
                DestinationAddress = $rule.DestinationAddressPrefix
                BestPractices = 'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview'
            }
            $results += $result
        }
    }
}

# Output results as a table if any found
if ($results) {
    $results | Format-Table -AutoSize
} else {
    Write-Host "No inbound rules allowing traffic from Internet found."
}
