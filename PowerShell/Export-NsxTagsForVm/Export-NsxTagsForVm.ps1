# version 0.91
# date: 2024.10.24
# Developed by Antony Stefanov (Antony.Stefanov@broadcom.com)
#
# PowerShell script that exports NSX tags assigned to VM in json or csv format
# Required Powershel modules:
# - VMware.VimAutomation.Core (PowerCLI) version 13.3

<# Sample imput JSON file:
#######################################################
{
    "vcenter": [
        {
			"fqdn": "<vCenter FQDN>",
            "username": "<vCenter user name>",
            "password":"<vCenter user password>",
            "clusters": [
                {"clusterName":"<vCenter cluster>"},
                {"clusterName":"<vCenter cluster>"}
            ]
        }
    ],
    "nsxManager":[
        
        {
            "fqdn": "<NSX FQDN>",
            "username": "<NSX user name>",
            "password":"<NSX user password>"
        }
    ],
    "Output": [
        {"fileName": "<Export File name>"},
        {"fileFormat": "< csv or json >"}
    ]
}

#######################################################
#>

# .Example
# Export-NsxTagsForVm.ps1 -inputJsonFile input-param.json

# General variables
param (
    [Parameter (Mandatory = $false)] [String]$inputJsonFilePath # = "input-param.json"
)

# Checking if input json file exists
if (Test-Path $inputJsonFilePath) {
    $inputParam = Get-Content -Path $inputJsonFilePath -Raw | ConvertFrom-Json
}
else {
    Write-Host $inputJsonFilePath + " file not found." -ForegroundColor Red
    Exit
}

$vcenter = $inputParam.vcenter.fqdn 
$vcenterUser = $inputParam.vcenter.username 
$vcenterPassword = $inputParam.vcenter.password 
$vcenterSecurePassword = ConvertTo-SecureString $vcenterPassword -AsPlainText -Force
$vcenterCred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $vcenterUser, $vcenterSecurePassword
$vcClusters = $inputParam.vcenter.clusters.clusterName
#$vcCluster = $inputParam.vcenter.clusterName
$nsxManager = $inputParam.nsxManager.fqdn
$nsxUser = $inputParam.nsxManager.username
$nsxPassword = $inputParam.nsxManager.password
$nsxSecurePassword = ConvertTo-SecureString $nsxPassword -AsPlainText -Force
$nsxCred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $nsxUser, $nsxSecurePassword
$exportFileName = $inputParam.output.filename
$exportFileFormat = $inputParam.Output.FileFormat



Connect-VIServer $vcenter -Credential $vcenterCred
foreach ($vcCluster in $vcClusters) {

    $VMs = get-cluster $vcCluster | ForEach-Object {get-vm | ForEach-Object { $_ | get-view } }
    
    $VMsArray = @()

    foreach ($VM in $VMs) {
        $vmId = $vm.Config.InstanceUuid
        $vmname = $vm.Config.Name
        $getUrl = "https://$nsxManager/api/v1/fabric/virtual-machines?external_id=$vmId"
        $getrequest = Invoke-RestMethod -Uri $getUrl -Authentication Basic -Credential $nsxCred -Method Get -ContentType "application/json" -SkipCertificateCheck
        foreach ($tags in $getrequest.results.tags) {
            $obj = New-Object System.Object
            $obj | Add-Member -type NoteProperty -name Vcenter -value $vcenter
            $obj | Add-Member -type NoteProperty -name Cluster -value $vcCluster
            $obj | Add-Member -type NoteProperty -name NsxManager -value $nsxManager
            $obj | Add-Member -type NoteProperty -name VMname -value $vmname
            $obj | Add-Member -type NoteProperty -name VMid -value $vmid
            $obj | Add-Member -type NoteProperty -name tags_scope -value $tags.scope
            $obj | Add-Member -type NoteProperty -name tags_tag -value $tags.tag
            $VMsArray += $obj
        }
        
    }
}

Write-Host "Exporting to " $exportFileName -ForegroundColor Green
switch ($exportFileFormat) {
    "json" {
        $tempExport = $VMsArray | ConvertTo-Json -Depth 3
        $tempExport
        $tempExport >  $exportFileName
        }
    "csv" {
        $tempExport = $VMsArray | ConvertTo-Csv
        $tempExport
        $tempExport >  $exportFileName
    }
    Default {}
}






