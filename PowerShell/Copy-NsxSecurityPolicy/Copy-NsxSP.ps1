# Developed by Antony Stefanov astefanov@vmware.com
# version 0.9.2
# date: 2023.06.27

# The script replicates NSX security policies with firewall rules including at least one nsx group for source or destination based on IP addresses or security tags, from source NSX LM to destination NSX LM.
# If the NSX groups, Rules or security policy exists on the destination, they are overwritten.

# Important Note: NSX tags should pre-exist on the destination NSX Manager

<# Features, versions and dependencies
Minimal VCF version: 4.5
Supported Source:
    single VCF workload domain
    single NSX LM
Supported Destination
    multiple VCF workload domains
    multiple NSX LMs
Supported NSX Security Policies
    multiple policies
Supported NSX Groups based on:
    multiple IP addresses
    multiple tags in single criteria (Note: Tags should exist on the destination)
    Group expression either of:
        "IPAddressExpression"
        "Condition"
        "NestedExpression"
Support of non-default (custom) NS service goups
Dependency

    Modules
        Module = 'PowerValidatedSolutions'; Version = '1.8.0'
        Module = 'PowerVCF'; Version = '2.2.0'
#>

#
<# Example command:

 Copy-NsxSP.ps1 -inputJsonFilePath "C:\work\input.json"

#>

<# Input file preparation

Converting plain password to secure string password:
* Option 1 - Providing password in the command line
ConvertTo-SecureString "Pa$$w0rd" -AsPlainText -Force | ConvertFrom-SecureString

* Option 2 - Reading password from host prompt:
Read-Host -AsSecureString | ConvertFrom-SecureString

# Sample input json file with source and destination workload domains
{
    "source": [
        
        {
            "type": "workloadDomain",
            "fqdn": "sddc-manager.vrack.vsphere.local",
            "username": "administrator@vsphere.local",
            "password": <secure string password>,
            "domain": "vi1"
        }
        
    ],
    "destination":[

        {
            "type": "workloadDomain",
            "fqdn": "sddc-manager.vrack.vsphere.local",
            "username": "administrator@vsphere.local",
            "password": <secure string password>,
            "domain": "vi2"
        }
    ],
    "NSXSecurityPolicy": [
        {
            "name": "Infra1"
        }
    ],
    "skipOnDestination":
        {
            "NSXGroup":[
                {"name":"linux"},
                {"name":"Windows"}
            ]
        }
}


# Sample json input file with source and destination NSX managers

{
    "source": [
        
        {
            "type": "nsxManager",
            "fqdn": "vip-nsxmanager-vi1.vrack.vsphere.local",
            "username": "admin",
            "password": <secure string password>
        }
        
    ],
    "destination":[

        {
            "type": "nsxManager",
            "fqdn": "vip-nsxmanager-vi2.vrack.vsphere.local",
            "username": "admin",
            "password": <secure string password>
        }
    ],
    "NSXSecurityPolicy": [
        {
            "name": "Infra1"
        }
    ],
    "skipOnDestination":
        {
            "NSXGroup":[
                {"name":"linux"},
                {"name":"Windows"}
            ]
        }
}

#>

# Main script parameters
param (
    [Parameter (Mandatory = $false)] [String]$inputJsonFilePath  = "input-NsxSP.json"
)

Function checkingRequireModules {
    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$moduleName,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$moduleVersion
    )
	
    if (-Not (Get-module | Where-Object { $_.Name -eq $moduleName -And [version]$_.Version -ge [version]$moduleVersion })) {
        if (-Not (Get-InstalledModule -Name $moduleName -MinimumVersion $moduleVersion -ErrorAction Ignore)) {
            if (-Not (Get-InstalledModule -Name $moduleName -ErrorAction Ignore)) {
                Write-Output "$moduleName module not installed."
                Write-Output "Use the command 'Install-Module -Name $moduleName -MinimumVersion $moduleVersion' to install from the PS Gallery"
                return $false
            }
            else {
                Write-Output "$moduleName does not meet the minimum version required: $moduleVersion"
                Write-Output "Use the command 'Update-Module -Name $moduleName' to update module to the latest version from the PS Gallery."
                return $false
            }
        }
        else {
            Write-Output "$moduleName module with minimum version $moduleVersion available, but not imported."
            Write-Output "Importing $moduleName version $moduleVersion ..."
            Import-Module $moduleName
            if (-Not (Get-module | Where-Object { $_.Name -eq $moduleName -And [version]$_.Version -ge [version]$moduleVersion })) {
                Write-Output "Error: importing $moduleName"
                Write-Output "Use the command 'Import-Module $moduleName' to manually import the module."
                return $false
            }
            else {
                Write-Output "$moduleName $moduleVersion successfully imported."
                return $true
            }
        }
    }
    else {
        Write-Output "Minimum required version of $moduleName found."
        return $true
    }
}


function Get-NsxtGroup {
    param (
        [Parameter (Mandatory = $true)] [String]$Name
    )

    Try {
        $requestingURL = "https://$nsxtmanager/policy/api/v1/infra/domains/default/groups/" + $Name
        Write-LogMessage -type INFO -Message "Getting the NSX group $name from $nsxtmanager"
        $response = Invoke-RestMethod -Method GET -URI $requestingURL -ContentType application/json -headers $nsxtHeaders # -SkipCertificateCheck
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }
    
}


function New-NsxtGroup {
    param (
        [Parameter (Mandatory = $true)] [String]$groupId,
        [Parameter (Mandatory = $true)] [String]$name,
        [Parameter (Mandatory = $false)] [String]$description,
        [Parameter (Mandatory = $true)] $expressionJson
    )



    $expression = $expressionJson | ConvertFrom-Json
    $desc = ""
    
    if ($description) {$desc = $description}

    switch ($expression.resource_type) {
        
        { ($_ -eq "IPAddressExpression") -or ($_ -eq "Condition") -or ($_ -eq "NestedExpression") } {

            $groupJson = @"
{
    "expression" : [
        $expressionJson
        ],

    "resource_type" : "Group",
    "id" : "$name",
    "display_name" : "$name",
    "description" : "$desc"
}
"@
            
        }

        default {
            Write-LogMessage -type ERROR -Message "Unsupported expression type: $($expression.resource_type)" -Colour Red
            exit
        }

    }

    
    Try {
        $requestingURL = "https://$nsxtmanager/policy/api/v1/infra/domains/default/groups/" + $groupId
        $Response = Invoke-RestMethod -Method PATCH -URI $requestingURL -ContentType application/json -headers $nsxtHeaders -body $groupJson #-SkipCertificateCheck
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }

}

function Get-NsxtSecurityPolicy {
    param (
        [Parameter (Mandatory = $true)] [String]$name
    )
    $policyId = $name.replace(" ", "_")
    Try {
        $requestingURL = "https://$nsxtmanager/policy/api/v1/infra/domains/default/security-policies/" + $policyId
        Write-LogMessage -type INFO -Message "Getting from $requestingURL"
        $response = Invoke-RestMethod -Method GET -URI $requestingURL -ContentType application/json -headers $nsxtHeaders  -SkipCertificateCheck
        $response
    }
    Catch {
        Write-Error $_.Exception.Message
    }   

}

function New-NsxtSecurityPolicy {
    param (
        [Parameter (Mandatory = $true)] [String]$name,
        [Parameter (Mandatory = $true)] [String]$displayName,
        [Parameter (Mandatory = $true)] [String]$category,
        [Parameter (Mandatory = $true)] $rulesJson,
        [Parameter (Mandatory = $true)] [int32]$rulesCount
    )
    
    if ($rulesCount -eq 1) {
    $json = @"
{
    "description": "$name",
    "display_name": "$displayName",
    "category": "$category",
    "rules": [
        $rulesJson
    ]
}
"@
    } else {
        $json = @"
{
    "description": "$name",
    "display_name": "$displayName",
    "category": "$category",
    "rules": 
        $rulesJson
}
"@        
    }
    $policyId = $name.replace(" ", "_")
    Try {
        $requestingURL = "https://$nsxtmanager/policy/api/v1/infra/domains/default/security-policies/" + $policyId
        
        $response = Invoke-RestMethod -Method PATCH -URI $requestingURL -ContentType application/json -headers $nsxtHeaders -body $json # -SkipCertificateCheck
        $response
    }
    Catch {

        Write-Error $_.Exception.Message
    }
    
}

function Get-NSserviceGroup {
    
    param (
        [Parameter (Mandatory = $true)] [String]$NSserviceGroupName
    )
    
    $NSserviceGroupName = $NSserviceGroupName.replace(" ", "_")
    Try {
        # ToDo NSX 3.2
        #$NSservicesGroupsRequestingURL = "https://$nsxtManager/policy/api/v1/ns-service-groups"

        # NSX 3.1
        $NSservicesGroupsRequestingURL = "https://$nsxtManager/api/v1/ns-service-groups"
        $responseNSservicesGroups = Invoke-RestMethod -Method GET -URI $NSservicesGroupsRequestingURL -ContentType application/json -headers $nsxtHeaders # -SkipCertificateCheck
        $FoundServiceGroup = $false
        foreach ($NSserviceGroup in $responseNSservicesGroups.results) {
            if ($NSserviceGroup.display_name.replace(" ","_") -eq $NSserviceGroupName) {
                $FoundServiceGroup = $true
                $NSserviceGroup

            }
        }
        If (!($FoundServiceGroup)) {
            # ToDo: List all non default NS service groups available
            #$customServiceGroups = $responseNSservicesGroups.results | Where-Object {($_.default_service -eq $false)}
            #Write-LogMessage -type WARNING -Message "$NSserviceGroupName not found in NSServiceGroups" -Colour yellow
        }
        
    } catch {
        Write-Error $_.Exception.Message
        break
    }

}

function Get-NSservice {
    
    param (
        [Parameter (Mandatory = $true)] [String]$NSserviceName
    )
    
    $NSserviceName = $NSserviceName.replace(" ", "_")
    Try {
        $NSservicesRequestingURL = "https://$nsxtManager/api/v1/ns-services"
        $responseNSservices = Invoke-RestMethod -Method GET -URI $NSservicesRequestingURL -ContentType application/json -headers $nsxtHeaders # -SkipCertificateCheck
        $FoundService = $fasle
        foreach ($NSservice in $responseNSservices.results) {
            if ($NSservice.display_name.replace(" ","_") -eq $NSserviceName) {
                $FoundService = $true
                $NSservice
            }
        }
        if (!($FoundService)) {
            #ToDo: List all non default NS services available
            #$customService = $responseNSservices.results | Where-Object {($_.default_service -eq $false)}
            #Write-LogMessage -type WARNING -Message "$NSserviceName not found in NSServices" -Colour yellow
        }
    } catch {
        Write-Error $_.Exception.Message
        break
    }

}

function Get-AllNSXservices {
    
    Try {
        $NSXservicesRequestingURL = "https://$nsxtManager/policy/api/v1/infra/services"
        $resultsNSXservices = Invoke-RestMethod -Method GET -URI $NSXservicesRequestingURL -ContentType application/json -headers $nsxtHeaders | Select-Object -ExpandProperty results
        return $resultsNSXservices
    } catch {
        Write-Error $_.Exception.Message
        break
    }

}


function Add-NSService {
    param (
        [Parameter (Mandatory = $true)] [PSCustomObject]$ServicesToAdd
    )

    
    #Main foreach structure to iterate through services from previous step
    foreach ($Service in $ServicesToAdd) {
        
        #Add the first 4 lines of the request body to the $Body variable , these are service properties
        $Body = "
        {
            ""description"": ""$($Service.description)"",
            ""display_name"": ""$($Service.display_name)"",
            ""_revision"": 0,
            ""service_entries"": ["
        
        #Nested loop to iterate through each service entry
        foreach ($Service_entry in $Service.service_entries) {
            <#If the service entry type is 'NestedServiceServiceEntry' add the lines in $Service_entry_text
            to the request body ($Body variable). These are service entry properties#>
            If ($Service_entry.resource_type -eq 'NestedServiceServiceEntry') {
                $Service_entry_text = "
                {
                    ""resource_type"": ""NestedServiceServiceEntry"",
                    ""display_name"": ""$($Service_entry.display_name)"",
                    ""nested_service_path"": ""$($Service_entry.nested_service_path)""
                },"
                $Body = $Body.Insert($Body.Length,"`n$Service_entry_text")
            }
    
            <#If the service entry type is 'L4PortSetServiceEntry' check if both source and destination ports
            are specified and, if true, add the lines in $Service_entry_text to the request body ($Body variable).
            These are service entry properties#>
            ElseIf ($Service_entry.resource_type -eq 'L4PortSetServiceEntry') {
                $sourcePorts = ($Service_entry | Select-Object -ExpandProperty source_ports) -join '","'
                $destinationPorts = ($Service_entry | Select-Object -ExpandProperty destination_ports) -join '","'
                
                If (!([string]::Isnullorempty($sourcePorts)) -and !([string]::Isnullorempty($destinationPorts))) {
                    $Service_entry_text = "
                    {
                        ""resource_type"": ""L4PortSetServiceEntry"",
                        ""display_name"": ""$($Service_entry.display_name)"",
                        ""destination_ports"": [
                            ""$destinationPorts""
                        ],
                        ""source_ports"": [
                            ""$sourcePorts""
                        ],
                        ""l4_protocol"": ""$($Service_entry.l4_protocol)""
                    },"
                }
    
                <#If the service entry type is 'L4PortSetServiceEntry' check if only source ports are specified and,
                if true, add the lines in $Service_entry_text to the request body ($Body variable). These are service
                entry properties#>
                If (!([string]::Isnullorempty($sourcePorts)) -and ([string]::Isnullorempty($destinationPorts))) {
                    $Service_entry_text = "
                    {
                        ""resource_type"": ""L4PortSetServiceEntry"",
                        ""display_name"": ""$($Service_entry.display_name)"",
                        ""source_ports"": [
                            ""$sourcePorts""
                        ],
                        ""l4_protocol"": ""$($Service_entry.l4_protocol)""
                    },"
                }
    
                <#If the service entry type is 'L4PortSetServiceEntry' check if only destination ports are specified
                and, if true, add the lines in $Service_entry_text to the request body ($Body variable). These are
                service entry properties#>
                If  (([string]::Isnullorempty($sourcePorts)) -and !([string]::Isnullorempty($destinationPorts))) {
                    $Service_entry_text = "
                    {
                        ""resource_type"": ""L4PortSetServiceEntry"",
                        ""display_name"": ""$($Service_entry.display_name)"",
                        ""destination_ports"": [
                            ""$destinationPorts""
                        ],
                        ""l4_protocol"": ""$($Service_entry.l4_protocol)""
                    },"
                }
    
                #Insert the text stored in variable $Service_entry_text at the end of the $Body variable
                $Body = $Body.Insert($Body.Length,"`n$Service_entry_text")
            }
        }
    
        #region Add closing characters to body and remove the comma from the last service entry in the array
        $ClosingText = '
            ]
        }'
    
        $Body = $Body.Insert($Body.Length,"`n$ClosingText")
        $Body = $Body.Remove($Body.LastIndexOf(','),1)
        #endregion Add closing characters to body and remove the comma from the last service entry in the array
    
        Write-LogMessage -type INFO -Message "Patching service $($Service.id)"

        $requestingURL = "https://$nsxtmanager/policy/api/v1/infra/services/" + $($Service.id)
        $Response = Invoke-RestMethod -Method PATCH -URI $requestingURL -ContentType application/json -headers $nsxtHeaders -body $Body #-SkipCertificateCheck


        #$Counter ++
    
        <#Message to show progress, Write-Host used for this example. Write-Progress or Write-Verbose may be more 
        appropriate but I personally like the ability to add color to the text.#>
        #Write-LogMessage -Type INFO -Message "Processed $Counter services of $($ServicesToAdd.Count)"
    }

}

#################################################################################################
#--------------------------------------     Main script   --------------------------------------# 
#################################################################################################

# Perform Prerequisite Check
## Check for PowerShell modules required to run the script

$requiredPSversion = (
    [pscustomobject]@{ Major = "5"; Minor = "1"; Edition ="Desktop" }
)

## Check for required PowerShell version

#if (($PSVersionTable.PSVersion.Major -eq "5") -and ($PSVersionTable.PSVersion.Minor -eq "1") -and ($PSVersionTable.PSEdition -eq "Desktop")) {
if (($PSVersionTable.PSVersion.Major -ge "5")) {
    Write-Output "Detected supported PowerShell version: $($PSversionTable.PSVersion.Major).$($PSversionTable.PSVersion.Minor) edition: $($PSVersionTable.PSEdition)"
} else {
    Write-Output "Min Required PS Version: $($requiredPSversion.major).$($requiredPSversion.minor) Edition: $($requiredPSversion.Edition)"
    Write-Output "Detected NOT supported PowerShell version: $($PSversionTable.PSVersion.Major).$($PSversionTable.PSVersion.Minor) edition: $($PSVersionTable.PSEdition)"
   exit
}

$requireModuleList = @(
    [pscustomobject]@{ Module = 'PowerValidatedSolutions'; Version = '1.8.0' }
    [pscustomobject]@{ Module = 'PowerVCF'; Version = '2.2.0' }
)

## Check if required modules have been imported

$errorModule = $false

Write-Output "Checking Required Modules"
foreach ($moduleItem in $requireModuleList) {
    $result = checkingRequireModules -moduleName $moduleItem.Module -moduleVersion $moduleItem.Version
    foreach ($line in $result) {
        if ($line -eq $false) {
            $errorModule = $true
        }
        elseif ($line -eq $true) {
        }
        else {
            Write-Output $line
        }
    }
}
if ($errorModule) {
    Write-Warning "Required PowerShell modules not found. Review messages messages and resolve before proceeding."
    Exit
}

# Initialize Script Log File

#Clear-Host; Write-Host ""
Start-SetupLogFile -Path $PSScriptRoot -ScriptName $MyInvocation.MyCommand.Name
Write-LogMessage -Type INFO -Message "Setting up the log file to path $logfile" -Colour yellow

# Checking if input json file exists
if (Test-Path $inputJsonFilePath) {
    $inputParam = Get-Content -Path $inputJsonFilePath -Raw | ConvertFrom-Json
}
else {
    Write-LogMessage -Type ERROR -Message $inputJsonFilePath + " file not found." -Colour Red
    Exit
}


# Start processing each of the NSX Security policies
Foreach ($policyName in $inputParam.NSXSecurityPolicy.name) {
    $foundErrors = 0
    Write-LogMessage -type INFO -Message "Start processing policy: $policyName" -Colour yellow
    Write-LogMessage -type INFO -Message "Reading source $($inputParam.source.fqdn)" -Colour yellow
    
    # Reading the NSX Security policy from source    
    try {
        switch ($inputParam.source.type) {
            "workloadDomain" {
                Write-LogMessage -type INFO -Message "Test VCF Connection to server $($inputParam.source.fqdn)"
                if (Test-VCFConnection -server $inputParam.source.fqdn) {
                    Write-LogMessage -type INFO -Message "Test VCF Authentication to server $($inputParam.source.fqdn)"
                    
                    #convert EncPass to plain text password
                    $encryptedPass = $inputParam.source.password
                    $secureStringPass  = ConvertTo-SecureString $encryptedPass
                    $sddcPlainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($secureStringPass))))

                    if (Test-VCFAuthentication -server $inputParam.source.fqdn -user $inputParam.source.username -pass $sddcPlainPass) {
                        $vcfNsxtDetails = Get-NsxtServerDetail -fqdn $inputParam.source.fqdn -username $inputParam.source.username -password $sddcPlainPass -domain $inputParam.source.domain
                        $nsxFqdn = $vcfNsxtDetails.fqdn
                        $nsxAdminUser = $vcfNsxtDetails.adminUser
                        $nsxAdminPass = $vcfNsxtDetails.adminPass
                    }
                    else {
                        Write-LogMessage -type ERROR -Message "Failed to Authenticate to SDDC manager $($inputParam.source.fqdn)" -Colour red
                        $foundErrors++
                        exit
                    }
                }
                else {
                    Write-LogMessage -type ERROR -Message "Failed to Connect to SDDC manager $($inputParam.source.fqdn)" -Colour red
                    $foundErrors++
                    exit
                }
            }
            "nsxManager" {
                $nsxFqdn = $inputParam.source.fqdn
                $nsxAdminUser = $inputParam.source.username
                
                # convert EncPass to plain text pass
                $encryptedPass = $inputParam.source.password
                $secureStringPass  = ConvertTo-SecureString $encryptedPass
                $nsxPlainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($secureStringPass))))

                $nsxAdminPass = $nsxPlainPass
            }
        }

        Write-LogMessage -type INFO -Message "Testing Connection to $nsxFqdn on port 443"
        if (Test-NetConnection -Port 443 -ComputerName $nsxFqdn) {
            
            Write-LogMessage -type INFO -Message "Testing NSXT Authentication to $nsxFqdn"

            if (Test-NSXTAuthentication -server $nsxFqdn -user $nsxAdminUser -pass $nsxAdminPass) {
                # Get the source security policy
                Write-LogMessage -type INFO -Message "Getting NSXT security policy $policyName from $nsxtmanager"
                if (Get-NsxtSecurityPolicy -Name $policyName) {
                    $securityPolicy = Get-NsxtSecurityPolicy -Name $policyName
                    Write-LogMessage -type INFO -Message "Found NSXT security policy `nid:$($securityPolicy.id) `ndisplay_name:$($securityPolicy.display_name) `nrules:$($securityPolicy.rules) `nraw policy:$securityPolicy in server:$nsxtmanager"
                    # Find unique security groups used in rules
                    $sourceGroups = @()
                    $destinationGroups = @()
                    $groups = @()

                    $sourceGroups = @($securityPolicy.rules.source_groups | Where-Object {$_ -ne "ANY" -and $_ -like "/infra/domains/default/groups/*" }  | Split-Path -Leaf)
                    $destinationGroups = @($securityPolicy.rules.destination_groups | Where-Object {$_ -ne "ANY" -and $_ -like "/infra/domains/default/groups/*"} | Split-Path -Leaf)
                    $groups = $sourceGroups + $destinationGroups | Select-Object -Unique
                    Write-LogMessage -type INFO -Message "Unique groups to proceed: $groups " -Colour yellow
                            
                    $destinationNsxtGroups = @()
                            
                    foreach ($group in $groups) {
                        if ($group -ne "ANY") {
                            try {
                                $nsxtGroup = Get-NsxtGroup -Name $group
                                $groupProperties = @{
                                    groupId          = $nsxtGroup.id
                                    groupDisplayName = $nsxtGroup.display_name
                                    groupDescription = $nsxtGroup.description
                                    groupExpression  = $nsxtGroup.expression
                                }   
                                $GroupObject = New-Object -TypeName PSObject -Property $groupProperties
                                $destinationNsxtGroups += $GroupObject
                            }
                            catch {
                                Write-LogMessage -type ERROR -Message "Error getting group: $group from $nsxtmanager"
                                Debug-CatchWriter -object $_
                                exit
                            }
                        }
                        else {
                            Write-LogMessage -type INFO -Message "Skipping group name: $group"
                        }
                        
                    }
                    $sourceNSserviceGroups = @()
                    $sourceNSserviceGroups = $securityPolicy.rules.services | Where-Object {$_ -ne "ANY"} | Select-Object -Unique | Split-Path -Leaf

                    #Filter only non default services
                    $customNSserviceGroups = @()
                    foreach ($svcName in $sourceNSserviceGroups){
                        $svc = Get-NSserviceGroup -NSserviceGroupName $svcName
                        if ($svc.default_service -eq $false) {
                            $customNSserviceGroups += $svc
                        }
                    }
                    $SrcNSXServicesResults = Get-AllNSXservices

                    Write-LogMessage -type INFO -Message "Found NSserviceGroups: $($customNSserviceGroups.display_name)" -colour yellow

                }
                else {
                    Write-LogMessage -type ERROR -Message "Error getting the security policy $policyName from $nsxtmanager" -Colour red
                    $foundErrors++
                    exit
                }
            }
            else {
                Write-LogMessage -type ERROR -Message "Failed to Authenticate to NSXT server $nsxFqdn" -Colour red
                $foundErrors++
                exit
            }
        }
        else {
            Write-LogMessage -type ERROR -Message "Failed to Connect to NSXT server $nsxFqdn" -Colour red
            $foundErrors++
            exit
        }
    }
    catch {
        Debug-CatchWriter -object $_
        exit
    }

    
    #if (($destinationNsxtGroups.Count -gt 0) -and ($foundErrors -eq 0) ) {
    if (($foundErrors -eq 0) ) {
        # Processing each of the Destinations 
        foreach ($destinationObject in $inputParam.destination) {
            Write-LogMessage -type INFO -Message "Processing destination $($destinationObject.fqdn)" -Colour yellow
            switch ($destinationObject.type) {
                "workloadDomain" {
                    Write-LogMessage -type INFO -Message "Test VCF Connection to server $($destinationObject.fqdn)"
                    if (Test-VCFConnection -server $destinationObject.fqdn) {
                        Write-LogMessage -type INFO -Message "Test VCF Authentication to server $($destinationObject.fqdn)"
                        
                        # Convert EncPass to plain text pass
                        $encryptedPass = $destinationObject.password
                        $secureStringPass  = ConvertTo-SecureString $encryptedPass
                        $sddcPlainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($secureStringPass))))

                        if (Test-VCFAuthentication -server $destinationObject.fqdn -user $destinationObject.username -pass $sddcPlainPass) {
                            $vcfNsxtDetails = Get-NsxtServerDetail -fqdn $destinationObject.fqdn -username $destinationObject.username -password $sddcPlainPass -domain $destinationObject.domain
                            $nsxFqdn = $vcfNsxtDetails.fqdn
                            $nsxAdminUser = $vcfNsxtDetails.adminUser
                            $nsxAdminPass = $vcfNsxtDetails.adminPass
                        }
                        else {
                            Write-LogMessage -type ERROR -Message "Failed to Authenticate to SDDC manager $($destinationObject.fqdn)" -Colour red
                            exit
                        }
                    }
                    else {
                        Write-LogMessage -type ERROR -Message "Failed to Connect to SDDC server $($destinationObject.fqdn)" -Colour red
                        exit
                    }
                }
                "nsxManager" {
                    $nsxFqdn = $destinationObject.fqdn
                    $nsxAdminUser = $destinationObject.username
                    
                    # Convert EncPass to plain text password
                    $encryptedPass = $destinationObject.password
                    $secureStringPass  = ConvertTo-SecureString $encryptedPass
                    $nsxPlainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($secureStringPass))))

                    $nsxAdminPass = $nsxPlainPass
                }
            }
            try {
                
                Write-LogMessage -type INFO -Message "Testing NSXT Connection to server $nsxFqdn"
                if (Test-NetConnection -Port 443 -ComputerName $nsxFqdn) {
                    
                    Write-LogMessage -type INFO -Message "Testing NSXT Authentication to server $nsxFqdn"
                    if (Test-NSXTAuthentication -server $nsxFqdn -user $nsxAdminUser -pass $nsxAdminPass) {
                        $nsxtProductVersion = ((Get-NsxtService -Name "com.vmware.nsx.node").get()).product_version

                        if ($customNSserviceGroups.Count -gt 0) {
                            Write-LogMessage -type INFO -Message "Searching for Custom Services: ($($customNSserviceGroups.display_name)) in destination" -Colour yellow
                        
                            # NSXservices
                            $DstNSXServicesResults = Get-AllNSXservices

                            $ServiceDiff = Compare-Object -ReferenceObject $SrcNSXServicesResults -DifferenceObject $DstNSXServicesResults -Property id | Select-Object -ExpandProperty id
                            $ServicesToAdd = $SrcNSXServicesResults | Where-Object id -in $ServiceDiff

                            
                            if (!($null -eq $ServicesToAdd)) {
                                Write-LogMessage -type INFO -Message "Custom Services to add in destination $ServicesToAdd"
                                Add-NSService -ServicesToAdd $ServicesToAdd
                            }
                            Write-LogMessage -type INFO -Message "Sleeping for 5 sec"
                            Start-Sleep -Seconds 5

                            foreach ($NSsvc in $customNSserviceGroups.display_name ) {
                                try {

                                    # Search for $NSsvc in NSServiceGroups
                                    $NSserviceGroupFound = $false
                                    $destServiceGroup = Get-NSserviceGroup -NSserviceGroupName $NSsvc
                                    if ($destServiceGroup) {
                                        $NSserviceGroupFound = $true
                                    } 
                                    
                                    # Search for $NSsvc in NSServices
                                    $NSserviceFound = $false
                                    $destService = Get-NSservice -NSserviceName $NSsvc
                                    if ($destService) {
                                        $NSserviceFound = $true
                                    }

                                    # Check if $NSsvc was found in NSServiceGroups or NSServices
                                    if (!($NSserviceGroupFound) -and !($NSserviceFound)) {
                                        Write-LogMessage -type ERROR -Message "Missing service or service group $NSsvc in $nsxFqdn :ERROR" -Colour Red
                                        exit
                                    } else {
                                        Write-LogMessage -type INFO -Message "Searching Service $NSsvc in $nsxFqdn : SUCCESS" -Colour Green
                                    }

                                } catch {
                                    Debug-CatchWriter -object $_
                                }
                            }
                        }
                        foreach ($nsxtGroup in $destinationNsxtGroups) {
                            Write-LogMessage -type INFO -Message "Patching NSXT group: $($nsxtGroup.groupDisplayName)"
                            if ($inputParam.skipOnDestination.NSXgroup.name.contains($nsxtGroup.groupDisplayName)) {
                                Write-LogMessage -type INFO -Message "NSX group: $($nsxtGroup.groupDisplayName) marked for skip on destination"
                                $nsxGroupExist = get-nsxtgroup -name $nsxtGroup.groupDisplayName
                                if ($nsxGroupExist.display_name -eq $nsxtGroup.groupDisplayName) {
                                    Write-LogMessage -type INFO -Message "Found NSX group: $($nsxtGroup.groupDisplayName)"
                                    Write-LogMessage -type WARNING -Message "Skipping on destination NSX group: $($nsxtGroup.groupDisplayName)" -Colour Yellow
                                } else {
                                    Write-LogMessage -type ERROR -Message "NSX group $($nsxtGroup.groupDisplayName) not found" -Colour Red
                                    exit
                                }
                            } else {
                                try {
                                    New-NsxtGroup -groupId $nsxtGroup.groupId -name $nsxtGroup.groupDisplayName -description $nsxtGroup.groupDescription -expression ($nsxtGroup.groupExpression | convertto-json)
                                } catch {
                                    Write-LogMessage -type ERROR -Message "Patching NSX group $($nsxtGroup.groupDisplayName) Failed" -Colour Red
                                    Debug-CatchWriter -object $_
                                }
                            }
                        }
                        # New security policy parameters
                        $destPolicyName = $securityPolicy.id
                        $destPolicyDisplayName = $securityPolicy.display_name
                        $destPolicyCategory = $securityPolicy.category
                        $destPolicyRules = $securityPolicy.rules | ConvertTo-Json -Depth 10
                        #Write-LogMessage -type INFO -Message "Destination policy rules JSON: $destPolicyRules "
                        Write-LogMessage -type INFO -Message "Patching security policy: $destPolicyName in server: $nsxtmanager"
                        try {
                            New-NsxtSecurityPolicy -name $destPolicyName -displayName $destPolicyDisplayName -category $destPolicyCategory -rulesJson $destPolicyRules -rulesCount $securityPolicy.rules.Count
                        } catch {
                            Debug-CatchWriter -object $_
                        }
                           
                    }
                    else {
                        Write-LogMessage -type ERROR -Message "Failed to Authenticate to NSXT $nsxFqdn" -Colour red
                        exit
                    }
                }
                else {
                    Write-LogMessage -type ERROR -Message "Failed to Connect to NSXT $nsxFqdn" -Colour red
                    exit
                }
                    
            }
            catch {
                Debug-CatchWriter -object $_
                exit
            }
        }
    }
    else {
        Write-LogMessage -type ERROR -Message "Rules in security policy $policyName does not contain groups" -Colour red
        exit
    }
}
