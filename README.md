## Overview

This repository contains various PowerShell scripts for managing Azure resources.

## Azure NSG Insecure Rule Analyzer

This repository contains PowerShell scripts for Azure resource management. The main script, `insecure-nsg.ps1`, analyzes all Network Security Groups (NSGs) in your current Azure subscription and identifies inbound rules that allow traffic from the Internet (i.e., source is `*` or `Internet`).

### Script: insecure-nsg.ps1

**Purpose:**
- Scans all NSGs for inbound rules that allow traffic from the Internet.
- Outputs a table with details of each insecure rule and a link to Azure network security best practices.

**Usage:**
1. Ensure you have the Az PowerShell module installed and are authenticated to Azure.
2. Run the script in a PowerShell session with appropriate permissions:
   ```powershell
   ./insecure-nsg.ps1
   ```

**Output:**
- A table listing NSG name, location, rule name, priority, protocol, port range, source/destination addresses, and a best practices link for each insecure rule.
- If no insecure rules are found, a message is displayed.

**Reference:**
- [Azure Network Security Best Practices](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-best-practices)
# powershell-scripts