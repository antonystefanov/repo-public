# version 0.9
# date: 2024.11.27
# Developed by Antony Stefanov (Antony.Stefanov@broadcom.com)
# 

# PowerShell script that exports NSX group memebers in json or txt format
# 
# Tested with PSVersion 7.4.5
#
# Required Powershel modules:
#   VMware.VimAutomation.Common     min version     13.3.0.24145081                
#   VMware.VimAutomation.Core       min version     13.3.0.24145081                  
#   VMware.VimAutomation.Nsxt       min version     13.3.0.24145081                  
    
 
<# Sample imput JSON file:
#######################################################
{
    "nsxManager":[
        
        {
            "fqdn": "<NSX FQDN>",
            "username": "<NSX admin user name>",
            "password":"<NSX user password>"
        }
    ],
    "Output": [
        {"fileFormat": "< txt or json >"}
    ]
}
#######################################################
#>

# .Example
# list-NsxGroupMembers.ps1 -inputJsonFile input-param.json

# General variables
param (
    [Parameter (Mandatory = $false)] [String]$inputJsonFilePath = "input-param.json"
)

# Checking if input json file exists
if (Test-Path $inputJsonFilePath) {
    $inputParam = Get-Content -Path $inputJsonFilePath -Raw | ConvertFrom-Json
}
else {
    Write-Host $inputJsonFilePath + " file not found." -ForegroundColor Red
    Exit
}

$nsxManager = $inputParam.nsxManager.fqdn
$nsxAdminUser = $inputParam.nsxManager.username
$nsxAdminPassword = $inputParam.nsxManager.password
$nsxSecurePassword = ConvertTo-SecureString $nsxAdminPassword -AsPlainText -Force
$nsxCred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $nsxAdminUser, $nsxSecurePassword
#$exportFileName = $inputParam.Output.filename
$exportFileFormat = $inputParam.Output.FileFormat

#Connect to NSX manager
Connect-NsxtServer -Server $nsxManager -Credential $nsxCred

$nsxGroupsArray = @()
# Get NSX groups
$uri1 = "https://$nsxManager/policy/api/v1/infra/domains/default/groups"
$NsxGroups = Invoke-RestMethod -Method GET -URI $uri1 -Authentication Basic -Credential $nsxCred -ContentType application/json -SkipCertificateCheck
Write-Host "NSX Groups found: ", $NsxGroups.results.id

#Get NSX group members
foreach ($nsxGroup in $NsxGroups.results) {
    $nsxGroupId = $nsxGroup.id
    $uri2 = "https://$nsxManager/policy/api/v1/infra/domains/default/groups/$nsxGroupId/members/virtual-machines"
    $members = Invoke-RestMethod -Method GET -URI $uri2 -Authentication Basic -Credential $nsxCred -ContentType application/json  -SkipCertificateCheck
    $obj = New-Object System.Object
    $obj | Add-Member -type NoteProperty -name NSX_group -value $nsxGroupId
    $obj | Add-Member -type NoteProperty -name VM_members -value $members.results.display_name
    $nsxGroupsArray += $obj
}

# Export NSX Group members to output file
switch ($exportFileFormat) {
    "json" {
        $tempExport = $nsxGroupsArray | ConvertTo-Json -Depth 5
        $tempExport >  "output.json"
        Write-host "Exported NSX Group Members to output.json" - -ForegroundColor Yellow
        }
    "csv" {
        New-Item -Path "output.csv" -ItemType File -Force
        add-content -path output.csv -Value ("NSX_group" + ";" + "VM_members")
        foreach ($item in $nsxGroupsArray) {add-content -path output.csv -value ($item.nsx_group + ";" + ($item.members -join ",")) } 
        Write-host "Exported NSX Group Members to output.csv" - -ForegroundColor Yellow
    }
    Default {}
}