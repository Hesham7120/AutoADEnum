<#
    Author: Hesham
#>

[CmdletBinding()]
param(
    [string]$PDC = '',
    [string]$DN = '',
    [ValidateSet('All', 'U', 'G', 'M', 'Users', 'Groups', 'Machines')]
    [string]$ObjType = 'All',
    [string]$Propertie = '',
    [string]$Property = '',
    [string]$Name = '',
    [string]$OutputDirectory = (Join-Path (Get-Location) ("ADEnum_Output_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [ValidateSet('Important', 'All', 'None')]
    [string]$AclScope = 'Important',
    [int]$MaxAclObjects = 2500,
    [int]$MaxGroupDepth = 8,
    [int]$LargeGroupThreshold = 100,
    [int]$StaleDays = 180,
    [int]$MaxConsoleRows = 40,
    [switch]$SkipGpo,
    [switch]$SkipTrust,
    [switch]$SkipSysvolScan,
    [switch]$NoCsv,
    [switch]$NoJson,
    [switch]$NoPowerPoint
)

$ErrorActionPreference = 'Stop'

$script:Findings = New-Object System.Collections.ArrayList
$script:AttackPaths = New-Object System.Collections.ArrayList
$script:RelationshipEdges = New-Object System.Collections.ArrayList
$script:FindingCounter = 0
$script:PathCounter = 0
$script:ADContext = $null

$script:DefaultGroupNames = @(
    'Access Control Assistance Operators',
    'Account Operators',
    'Administrators',
    'Allowed RODC Password Replication',
    'Allowed RODC Password Replication Group',
    'Backup Operators',
    'Certificate Service DCOM Access',
    'Cert Publishers',
    'Cloneable Domain Controllers',
    'Cryptographic Operators',
    'Denied RODC Password Replication',
    'Denied RODC Password Replication Group',
    'Device Owners',
    'DHCP Administrators',
    'DHCP Users',
    'Distributed COM Users',
    'DnsAdmins',
    'DnsUpdateProxy',
    'Domain Admins',
    'Domain Computers',
    'Domain Controllers',
    'Domain Guests',
    'Domain Users',
    'Enterprise Admins',
    'Enterprise Key Admins',
    'Enterprise Read-only Domain Controllers',
    'Event Log Readers',
    'Group Policy Creator Owners',
    'Guests',
    'Hyper-V Administrators',
    'IIS_IUSRS',
    'Incoming Forest Trust Builders',
    'Key Admins',
    'Network Configuration Operators',
    'Performance Log Users',
    'Performance Monitor Users',
    'Pre-Windows 2000 Compatible Access',
    'Pre-Windows 2000 Compatible Access Group',
    'Print Operators',
    'Protected Users',
    'RAS and IAS Servers',
    'RDS Endpoint Servers',
    'RDS Management Servers',
    'RDS Remote Access Servers',
    'Read-only Domain Controllers',
    'Remote Desktop Users',
    'Remote Management Users',
    'Replicator',
    'Schema Admins',
    'Server Operators',
    'Storage Replica Administrators',
    'System Managed Accounts',
    'System Managed Accounts Group',
    'Terminal Server License Servers',
    'Users',
    'Windows Authorization Access',
    'Windows Authorization Access Group',
    'WinRMRemoteWMIUsers_'
)

$script:CriticalGroupNames = @(
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Key Admins',
    'Enterprise Key Admins',
    'Hyper-V Administrators'
)

$script:DangerousGroupNames = @(
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Key Admins',
    'Enterprise Key Admins',
    'Hyper-V Administrators',
    'Remote Desktop Users',
    'Remote Management Users',
    'Distributed COM Users',
    'Windows Authorization Access Group',
    'Pre-Windows 2000 Compatible Access',
    'Pre-Windows 2000 Compatible Access Group',
    'Certificate Service DCOM Access',
    'Cert Publishers',
    'Incoming Forest Trust Builders'
)

function Write-Section {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [ConsoleColor]$Color = [ConsoleColor]::Blue
    )

    $line = ('=' * 18) + " $Name " + ('=' * 18)
    Write-Host ''
    Write-Host $line -ForegroundColor $Color
}

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Blue
    )

    Write-Host ("[*] {0}" -f $Message) -ForegroundColor $Color
}

function Get-RiskRank {
    param([string]$Risk)

    switch ($Risk) {
        'Critical' { return 4 }
        'Medium' { return 3 }
        'Low' { return 2 }
        'Info' { return 1 }
        default { return 0 }
    }
}

function Get-RiskColor {
    param([string]$Risk)

    switch ($Risk) {
        'Critical' { return [ConsoleColor]::Red }
        'Medium' { return [ConsoleColor]::Yellow }
        'Low' { return [ConsoleColor]::Green }
        'Info' { return [ConsoleColor]::Green }
        default { return [ConsoleColor]::Blue }
    }
}

function ConvertTo-DisplayString {
    param(
        [object]$Value,
        [int]$MaxLength = 44
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [datetime]) {
        $text = $Value.ToString('yyyy-MM-dd HH:mm')
    }
    elseif ($Value -is [array]) {
        $text = (($Value | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) -join '; ')
    }
    else {
        $text = [string]$Value
    }

    $text = $text -replace '\s+', ' '
    if ($text.Length -gt $MaxLength) {
        return $text.Substring(0, [Math]::Max(0, $MaxLength - 3)) + '...'
    }

    return $text
}

function Write-StructuredTable {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [string]$RiskProperty = 'Risk',
        [int]$MaxRows = 40
    )

    if ($null -eq $Rows -or $Rows.Count -eq 0) {
        Write-Host 'No records.' -ForegroundColor Green
        return
    }

    $rowsToShow = @($Rows | Select-Object -First $MaxRows)
    $widths = @{}
    foreach ($column in $Columns) {
        $max = $column.Length
        foreach ($row in $rowsToShow) {
            $value = ConvertTo-DisplayString -Value $row.$column -MaxLength 44
            if ($value.Length -gt $max) {
                $max = $value.Length
            }
        }
        $widths[$column] = [Math]::Min([Math]::Max($max, 8), 44)
    }

    $header = ($Columns | ForEach-Object { $_.PadRight($widths[$_]) }) -join '  '
    Write-Host $header -ForegroundColor Blue
    Write-Host (($Columns | ForEach-Object { '-' * $widths[$_] }) -join '  ') -ForegroundColor Blue

    foreach ($row in $rowsToShow) {
        $risk = $null
        if ($row.PSObject.Properties.Name -contains $RiskProperty) {
            $risk = [string]$row.$RiskProperty
        }

        $line = ($Columns | ForEach-Object {
                $value = ConvertTo-DisplayString -Value $row.$_ -MaxLength $widths[$_]
                $value.PadRight($widths[$_])
            }) -join '  '

        Write-Host $line -ForegroundColor (Get-RiskColor -Risk $risk)
    }

    if ($Rows.Count -gt $MaxRows) {
        Write-Host ("Showing {0} of {1} rows. Full data is exported to disk." -f $MaxRows, $Rows.Count) -ForegroundColor Yellow
    }
}

function ConvertTo-StringArray {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [byte[]]) {
        return @([Convert]::ToBase64String($Value))
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return @()
        }
        return @($Value)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    }

    return @([string]$Value)
}

function Convert-FileTime {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        if ($Value -is [array]) {
            if ($Value.Count -eq 0) {
                return $null
            }
            $Value = $Value[0]
        }

        $ticks = [int64]$Value
        if ($ticks -le 0 -or $ticks -eq 9223372036854775807) {
            return $null
        }

        return [DateTime]::FromFileTimeUtc($ticks).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Convert-LdapSid {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        if ($Value -is [System.Security.Principal.SecurityIdentifier]) {
            return $Value.Value
        }

        if ($Value -is [byte[]]) {
            return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value
        }

        return [string]$Value
    }
    catch {
        return $null
    }
}

function Resolve-SidName {
    param([object]$Sid)

    try {
        $sidString = Convert-LdapSid -Value $Sid
        if ([string]::IsNullOrWhiteSpace($sidString)) {
            return $null
        }

        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidString)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return [string]$Sid
    }
}

function Get-UacFlagNames {
    param([int]$UserAccountControl)

    $flags = @(
        @{ Name = 'SCRIPT'; Value = 0x00000001 },
        @{ Name = 'ACCOUNTDISABLE'; Value = 0x00000002 },
        @{ Name = 'HOMEDIR_REQUIRED'; Value = 0x00000008 },
        @{ Name = 'LOCKOUT'; Value = 0x00000010 },
        @{ Name = 'PASSWD_NOTREQD'; Value = 0x00000020 },
        @{ Name = 'PASSWD_CANT_CHANGE'; Value = 0x00000040 },
        @{ Name = 'ENCRYPTED_TEXT_PWD_ALLOWED'; Value = 0x00000080 },
        @{ Name = 'TEMP_DUPLICATE_ACCOUNT'; Value = 0x00000100 },
        @{ Name = 'NORMAL_ACCOUNT'; Value = 0x00000200 },
        @{ Name = 'INTERDOMAIN_TRUST_ACCOUNT'; Value = 0x00000800 },
        @{ Name = 'WORKSTATION_TRUST_ACCOUNT'; Value = 0x00001000 },
        @{ Name = 'SERVER_TRUST_ACCOUNT'; Value = 0x00002000 },
        @{ Name = 'DONT_EXPIRE_PASSWORD'; Value = 0x00010000 },
        @{ Name = 'MNS_LOGON_ACCOUNT'; Value = 0x00020000 },
        @{ Name = 'SMARTCARD_REQUIRED'; Value = 0x00040000 },
        @{ Name = 'TRUSTED_FOR_DELEGATION'; Value = 0x00080000 },
        @{ Name = 'NOT_DELEGATED'; Value = 0x00100000 },
        @{ Name = 'USE_DES_KEY_ONLY'; Value = 0x00200000 },
        @{ Name = 'DONT_REQ_PREAUTH'; Value = 0x00400000 },
        @{ Name = 'PASSWORD_EXPIRED'; Value = 0x00800000 },
        @{ Name = 'TRUSTED_TO_AUTH_FOR_DELEGATION'; Value = 0x01000000 },
        @{ Name = 'PARTIAL_SECRETS_ACCOUNT'; Value = 0x04000000 }
    )

    return @($flags | Where-Object { ($UserAccountControl -band $_.Value) -ne 0 } | ForEach-Object { $_.Name })
}

function Test-UacFlag {
    param(
        [int]$UserAccountControl,
        [int]$Flag
    )

    return (($UserAccountControl -band $Flag) -eq $Flag)
}

function Get-GroupTypeInfo {
    param([object]$GroupType)

    $value = [int64]0
    if ($null -ne $GroupType) {
        $value = [int64]$GroupType
    }

    $scope = 'Unknown'
    if (($value -band 0x00000002) -ne 0) { $scope = 'Global' }
    elseif (($value -band 0x00000004) -ne 0) { $scope = 'DomainLocal' }
    elseif (($value -band 0x00000008) -ne 0) { $scope = 'Universal' }

    $category = 'Distribution'
    if (($value -band 0x80000000) -ne 0) {
        $category = 'Security'
    }

    return [pscustomobject]@{
        Scope = $scope
        Category = $category
        Raw = $value
    }
}

function Escape-LdapFilterValue {
    param([string]$Value)

    if ($null -eq $Value) {
        return ''
    }

    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Initialize-ADContext {
    param(
        [string]$Server,
        [string]$SearchBase
    )

    $domainObject = $null
    try {
        $domainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
    catch {
        if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($SearchBase)) {
            throw "Unable to discover the current domain. Provide -PDC and -DN when running from a non-domain context. Original error: $($_.Exception.Message)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($Server) -and $null -ne $domainObject) {
        $Server = $domainObject.PdcRoleOwner.Name
    }

    $rootPath = 'LDAP://RootDSE'
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $rootPath = "LDAP://$Server/RootDSE"
    }

    $rootDse = [ADSI]$rootPath
    if ([string]::IsNullOrWhiteSpace($SearchBase)) {
        $SearchBase = [string]$rootDse.defaultNamingContext
    }

    $configurationNamingContext = [string]$rootDse.configurationNamingContext
    $schemaNamingContext = [string]$rootDse.schemaNamingContext
    $domainFunctionality = [string]$rootDse.domainFunctionality
    $forestFunctionality = [string]$rootDse.forestFunctionality

    $entryPath = "LDAP://$SearchBase"
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $entryPath = "LDAP://$Server/$SearchBase"
    }

    $domainEntry = New-Object System.DirectoryServices.DirectoryEntry($entryPath)
    $dnsRoot = $null
    try {
        $dnsRoot = [string]$domainEntry.Properties['dnsRoot'][0]
    }
    catch {
        if ($null -ne $domainObject) {
            $dnsRoot = $domainObject.Name
        }
    }

    return [pscustomobject]@{
        Server = $Server
        DistinguishedName = $SearchBase
        DomainEntry = $domainEntry
        RootDse = $rootDse
        DnsRoot = $dnsRoot
        NetBIOSName = $null
        ConfigurationNamingContext = $configurationNamingContext
        SchemaNamingContext = $schemaNamingContext
        DomainFunctionality = $domainFunctionality
        ForestFunctionality = $forestFunctionality
        GeneratedAt = Get-Date
    }
}

function New-LdapPath {
    param([string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($script:ADContext.Server)) {
        return "LDAP://$DistinguishedName"
    }

    return "LDAP://$($script:ADContext.Server)/$DistinguishedName"
}

function Search-Ldap {
    param(
        [Parameter(Mandatory = $true)][string]$Filter,
        [string[]]$Properties = @(),
        [System.DirectoryServices.DirectoryEntry]$SearchRoot = $script:ADContext.DomainEntry,
        [System.DirectoryServices.SearchScope]$Scope = [System.DirectoryServices.SearchScope]::Subtree
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($SearchRoot)
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 0
    $searcher.SearchScope = $Scope
    $searcher.CacheResults = $false
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

    foreach ($property in $Properties) {
        if ($property -ne '*') {
            [void]$searcher.PropertiesToLoad.Add($property)
        }
    }

    try {
        $results = $searcher.FindAll()
        $items = @()
        foreach ($result in $results) {
            $items += $result
        }
        return $items
    }
    finally {
        if ($null -ne $results) {
            $results.Dispose()
        }
        $searcher.Dispose()
    }
}

function Get-LdapProperty {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.SearchResult]$Result,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $key = $Name.ToLowerInvariant()
    if ($Result.Properties.Contains($key)) {
        $values = @($Result.Properties[$key])
        if ($values.Count -eq 1) {
            return $values[0]
        }
        return $values
    }

    return $null
}

function Get-LdapPropertyList {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.SearchResult]$Result,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return ConvertTo-StringArray -Value (Get-LdapProperty -Result $Result -Name $Name)
}

function Test-RangedLdapProperty {
    param(
        [System.DirectoryServices.SearchResult]$Result,
        [string]$AttributeName
    )

    foreach ($propertyName in $Result.Properties.PropertyNames) {
        if ($propertyName -like "$AttributeName;range=*") {
            return $true
        }
    }

    return $false
}

function Get-RangedLdapAttribute {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$AttributeName
    )

    $values = New-Object System.Collections.ArrayList
    $rangeStart = 0
    $rangeStep = 1499
    $finished = $false
    $entry = New-Object System.DirectoryServices.DirectoryEntry((New-LdapPath -DistinguishedName $DistinguishedName))

    try {
        while (-not $finished) {
            $rangeEnd = $rangeStart + $rangeStep
            $rangeProperty = '{0};range={1}-{2}' -f $AttributeName, $rangeStart, $rangeEnd
            $entry.RefreshCache(@($rangeProperty))

            $returnedProperty = $null
            foreach ($propertyName in $entry.Properties.PropertyNames) {
                if ($propertyName -like "$AttributeName;range=$rangeStart-*") {
                    $returnedProperty = $propertyName
                    break
                }
            }

            if ($null -eq $returnedProperty) {
                break
            }

            foreach ($value in $entry.Properties[$returnedProperty]) {
                [void]$values.Add([string]$value)
            }

            if ($returnedProperty -like '*-*') {
                if ($returnedProperty.EndsWith('*')) {
                    $finished = $true
                }
            }

            $rangeStart = $rangeEnd + 1
            if ($rangeStart -gt 1000000) {
                $finished = $true
            }
        }
    }
    catch {
        Write-Status -Message ("Range retrieval failed for {0} on {1}: {2}" -f $AttributeName, $DistinguishedName, $_.Exception.Message) -Color Yellow
    }
    finally {
        $entry.Dispose()
    }

    return @($values)
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'Medium', 'Low', 'Info')][string]$Risk,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Category,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ObjectType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [string]$Target = '',
        [string]$DistinguishedName = '',
        [string]$AttackVector = '',
        [string]$Evidence = '',
        [string]$Impact = '',
        [string]$Recommendation = '',
        [string[]]$Tags = @()
    )

    $script:FindingCounter++
    $finding = [pscustomobject]@{
        Id = ('F-{0:D4}' -f $script:FindingCounter)
        Risk = $Risk
        RiskRank = Get-RiskRank -Risk $Risk
        Category = $Category
        ObjectType = $ObjectType
        Name = $Name
        Target = $Target
        DistinguishedName = $DistinguishedName
        AttackVector = $AttackVector
        Evidence = $Evidence
        Impact = $Impact
        Recommendation = $Recommendation
        Tags = $Tags
    }

    [void]$script:Findings.Add($finding)
    return $finding
}

function Add-RelationshipEdge {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Relationship,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Target,
        [string]$Risk = 'Info',
        [string]$Evidence = ''
    )

    $edge = [pscustomobject]@{
        Source = $Source
        Relationship = $Relationship
        Target = $Target
        Risk = $Risk
        RiskRank = Get-RiskRank -Risk $Risk
        Evidence = $Evidence
    }

    [void]$script:RelationshipEdges.Add($edge)
    return $edge
}

function Add-AttackPath {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'Medium', 'Low', 'Info')][string]$Risk,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Start,
        [Parameter(Mandatory = $true)][string[]]$Steps,
        [string]$End = '',
        [string]$Evidence = '',
        [string]$Recommendation = ''
    )

    $script:PathCounter++
    $path = [pscustomobject]@{
        Id = ('P-{0:D4}' -f $script:PathCounter)
        Risk = $Risk
        RiskRank = Get-RiskRank -Risk $Risk
        Name = $Name
        Start = $Start
        Steps = $Steps
        End = $End
        Evidence = $Evidence
        Recommendation = $Recommendation
    }

    [void]$script:AttackPaths.Add($path)
    return $path
}

function Convert-ObjectForCsv {
    param([object[]]$InputObject)

    foreach ($item in $InputObject) {
        $hash = [ordered]@{}
        foreach ($property in $item.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [array]) {
                $hash[$property.Name] = (($value | ForEach-Object { [string]$_ }) -join '; ')
            }
            elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string] -and $value -isnot [byte[]]) {
                $hash[$property.Name] = (($value | ForEach-Object { [string]$_ }) -join '; ')
            }
            else {
                $hash[$property.Name] = $value
            }
        }
        [pscustomobject]$hash
    }
}

function Test-DefaultGroup {
    param([string]$GroupName)

    return ($script:DefaultGroupNames -contains $GroupName)
}

function Test-CriticalGroup {
    param([string]$GroupName)

    return ($script:CriticalGroupNames -contains $GroupName)
}

function Test-DangerousGroup {
    param([string]$GroupName)

    return ($script:DangerousGroupNames -contains $GroupName)
}

function Test-OutdatedOperatingSystem {
    param([string]$OperatingSystem)

    if ([string]::IsNullOrWhiteSpace($OperatingSystem)) {
        return $false
    }

    $legacyPatterns = @(
        'Windows 2000',
        'Windows XP',
        'Windows Vista',
        'Windows 7',
        'Windows 8',
        'Windows Server 2003',
        'Windows Server 2008',
        'Windows Server 2012',
        'Windows 10'
    )

    foreach ($pattern in $legacyPatterns) {
        if ($OperatingSystem -like "*$pattern*") {
            return $true
        }
    }

    return $false
}

function Get-PrincipalDisplayName {
    param(
        [string]$DistinguishedName,
        [hashtable]$ObjectByDn
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return ''
    }

    if ($ObjectByDn.ContainsKey($DistinguishedName)) {
        $obj = $ObjectByDn[$DistinguishedName]
        if ($obj.PSObject.Properties.Name -contains 'SamAccountName' -and -not [string]::IsNullOrWhiteSpace($obj.SamAccountName)) {
            return $obj.SamAccountName
        }

        if ($obj.PSObject.Properties.Name -contains 'Name' -and -not [string]::IsNullOrWhiteSpace($obj.Name)) {
            return $obj.Name
        }
    }

    return $DistinguishedName
}

function Get-EffectiveGroupDns {
    param(
        [string[]]$DirectMemberOf,
        [hashtable]$GroupsByDn,
        [int]$DepthLimit
    )

    $seen = @{}

    function Add-ParentGroup {
        param(
            [string]$GroupDn,
            [int]$Depth,
            [hashtable]$SeenGroups,
            [hashtable]$GroupLookup,
            [int]$MaxDepth
        )

        if ([string]::IsNullOrWhiteSpace($GroupDn) -or $Depth -gt $MaxDepth) {
            return
        }

        if ($SeenGroups.ContainsKey($GroupDn)) {
            return
        }

        $SeenGroups[$GroupDn] = $true
        if ($GroupLookup.ContainsKey($GroupDn)) {
            foreach ($parent in $GroupLookup[$GroupDn].MemberOf) {
                Add-ParentGroup -GroupDn $parent -Depth ($Depth + 1) -SeenGroups $SeenGroups -GroupLookup $GroupLookup -MaxDepth $MaxDepth
            }
        }
    }

    foreach ($groupDn in $DirectMemberOf) {
        Add-ParentGroup -GroupDn $groupDn -Depth 0 -SeenGroups $seen -GroupLookup $GroupsByDn -MaxDepth $DepthLimit
    }

    return @($seen.Keys)
}

function Get-RecursiveGroupMembers {
    param(
        [string]$GroupDn,
        [hashtable]$GroupsByDn,
        [int]$DepthLimit
    )

    $seen = @{}

    function Add-ChildMember {
        param(
            [string]$MemberDn,
            [int]$Depth,
            [hashtable]$SeenMembers,
            [hashtable]$GroupLookup,
            [int]$MaxDepth
        )

        if ([string]::IsNullOrWhiteSpace($MemberDn) -or $Depth -gt $MaxDepth) {
            return
        }

        if ($SeenMembers.ContainsKey($MemberDn)) {
            return
        }

        $SeenMembers[$MemberDn] = $true
        if ($GroupLookup.ContainsKey($MemberDn)) {
            foreach ($nestedMember in $GroupLookup[$MemberDn].Members) {
                Add-ChildMember -MemberDn $nestedMember -Depth ($Depth + 1) -SeenMembers $SeenMembers -GroupLookup $GroupLookup -MaxDepth $MaxDepth
            }
        }
    }

    if ($GroupsByDn.ContainsKey($GroupDn)) {
        foreach ($member in $GroupsByDn[$GroupDn].Members) {
            Add-ChildMember -MemberDn $member -Depth 0 -SeenMembers $seen -GroupLookup $GroupsByDn -MaxDepth $DepthLimit
        }
    }

    return @($seen.Keys)
}

function Get-ADUsersAdvanced {
    Write-Status -Message 'Collecting users, roastable accounts, delegation flags, and sensitive attributes.'

    $properties = @(
        'distinguishedName',
        'objectSid',
        'sAMAccountName',
        'cn',
        'displayName',
        'description',
        'userPrincipalName',
        'servicePrincipalName',
        'memberOf',
        'adminCount',
        'userAccountControl',
        'lastLogonTimestamp',
        'pwdLastSet',
        'whenCreated',
        'whenChanged',
        'primaryGroupID',
        'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity',
        'accountExpires',
        'badPwdCount',
        'lockoutTime',
        'logonCount'
    )

    $results = Search-Ldap -Filter '(&(objectCategory=person)(objectClass=user)(samAccountType=805306368))' -Properties $properties
    $users = New-Object System.Collections.ArrayList

    foreach ($result in $results) {
        $uac = [int](Get-LdapProperty -Result $result -Name 'userAccountControl')
        $spns = Get-LdapPropertyList -Result $result -Name 'servicePrincipalName'
        $delegateTo = Get-LdapPropertyList -Result $result -Name 'msDS-AllowedToDelegateTo'
        $rbcd = Get-LdapProperty -Result $result -Name 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $adminCountValue = Get-LdapProperty -Result $result -Name 'adminCount'
        $adminCount = $false
        if ($null -ne $adminCountValue) {
            $adminCount = ([int]$adminCountValue -eq 1)
        }

        $lastLogon = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'lastLogonTimestamp')
        $pwdLastSet = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'pwdLastSet')

        $isDisabled = Test-UacFlag -UserAccountControl $uac -Flag 0x00000002
        $user = [pscustomobject]@{
            ObjectType = 'User'
            DistinguishedName = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
            ObjectSid = Convert-LdapSid -Value (Get-LdapProperty -Result $result -Name 'objectSid')
            SamAccountName = [string](Get-LdapProperty -Result $result -Name 'sAMAccountName')
            CommonName = [string](Get-LdapProperty -Result $result -Name 'cn')
            DisplayName = [string](Get-LdapProperty -Result $result -Name 'displayName')
            UserPrincipalName = [string](Get-LdapProperty -Result $result -Name 'userPrincipalName')
            Description = [string](Get-LdapProperty -Result $result -Name 'description')
            UserAccountControl = $uac
            UacFlags = Get-UacFlagNames -UserAccountControl $uac
            AdminCount = $adminCount
            IsDisabled = $isDisabled
            PasswordNeverExpires = (Test-UacFlag -UserAccountControl $uac -Flag 0x00010000)
            PasswordNotRequired = (Test-UacFlag -UserAccountControl $uac -Flag 0x00000020)
            SmartcardRequired = (Test-UacFlag -UserAccountControl $uac -Flag 0x00040000)
            DontRequirePreAuth = (Test-UacFlag -UserAccountControl $uac -Flag 0x00400000)
            IsAsRepRoastable = ((Test-UacFlag -UserAccountControl $uac -Flag 0x00400000) -and -not $isDisabled)
            ServicePrincipalNames = $spns
            IsKerberoastable = (($spns.Count -gt 0) -and -not $isDisabled)
            MemberOf = Get-LdapPropertyList -Result $result -Name 'memberOf'
            EffectiveGroupDns = @()
            EffectiveGroupNames = @()
            IsPrivileged = $false
            PrivilegeReason = ''
            PrimaryGroupID = [string](Get-LdapProperty -Result $result -Name 'primaryGroupID')
            LastLogonTimestamp = $lastLogon
            PwdLastSet = $pwdLastSet
            AccountExpires = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'accountExpires')
            BadPwdCount = [string](Get-LdapProperty -Result $result -Name 'badPwdCount')
            LockoutTime = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'lockoutTime')
            LogonCount = [string](Get-LdapProperty -Result $result -Name 'logonCount')
            UnconstrainedDelegation = (Test-UacFlag -UserAccountControl $uac -Flag 0x00080000)
            ConstrainedDelegation = ($delegateTo.Count -gt 0)
            ProtocolTransition = (Test-UacFlag -UserAccountControl $uac -Flag 0x01000000)
            DelegatesTo = $delegateTo
            ResourceBasedConstrainedDelegation = ($null -ne $rbcd)
            WhenCreated = [string](Get-LdapProperty -Result $result -Name 'whenCreated')
            WhenChanged = [string](Get-LdapProperty -Result $result -Name 'whenChanged')
        }

        [void]$users.Add($user)
    }

    return @($users)
}

function Get-ADGroupsAdvanced {
    Write-Status -Message 'Collecting groups, default/custom classification, members, and nesting inputs.'

    $properties = @(
        'distinguishedName',
        'objectSid',
        'sAMAccountName',
        'cn',
        'description',
        'member',
        'memberOf',
        'groupType',
        'adminCount',
        'managedBy',
        'whenCreated',
        'whenChanged'
    )

    $results = Search-Ldap -Filter '(&(objectCategory=group)(objectClass=group))' -Properties $properties
    $groups = New-Object System.Collections.ArrayList

    foreach ($result in $results) {
        $dn = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
        $memberValues = Get-LdapPropertyList -Result $result -Name 'member'
        if ((Test-RangedLdapProperty -Result $result -AttributeName 'member') -or ($memberValues.Count -eq 0 -and $null -ne $dn)) {
            $rangedMembers = Get-RangedLdapAttribute -DistinguishedName $dn -AttributeName 'member'
            if ($rangedMembers.Count -gt $memberValues.Count) {
                $memberValues = $rangedMembers
            }
        }

        $sam = [string](Get-LdapProperty -Result $result -Name 'sAMAccountName')
        $typeInfo = Get-GroupTypeInfo -GroupType (Get-LdapProperty -Result $result -Name 'groupType')
        $adminCountValue = Get-LdapProperty -Result $result -Name 'adminCount'
        $adminCount = $false
        if ($null -ne $adminCountValue) {
            $adminCount = ([int]$adminCountValue -eq 1)
        }

        $group = [pscustomobject]@{
            ObjectType = 'Group'
            DistinguishedName = $dn
            ObjectSid = Convert-LdapSid -Value (Get-LdapProperty -Result $result -Name 'objectSid')
            SamAccountName = $sam
            Name = [string](Get-LdapProperty -Result $result -Name 'cn')
            Description = [string](Get-LdapProperty -Result $result -Name 'description')
            GroupScope = $typeInfo.Scope
            GroupCategory = $typeInfo.Category
            GroupTypeRaw = $typeInfo.Raw
            IsDefaultGroup = (Test-DefaultGroup -GroupName $sam)
            IsCriticalGroup = (Test-CriticalGroup -GroupName $sam)
            IsDangerousGroup = (Test-DangerousGroup -GroupName $sam)
            AdminCount = $adminCount
            ManagedBy = [string](Get-LdapProperty -Result $result -Name 'managedBy')
            Members = $memberValues
            MemberCount = $memberValues.Count
            NestedMembers = @()
            NestedMemberCount = 0
            MemberOf = Get-LdapPropertyList -Result $result -Name 'memberOf'
            WhenCreated = [string](Get-LdapProperty -Result $result -Name 'whenCreated')
            WhenChanged = [string](Get-LdapProperty -Result $result -Name 'whenChanged')
        }

        [void]$groups.Add($group)
    }

    return @($groups)
}

function Get-ADComputersAdvanced {
    Write-Status -Message 'Collecting computers, domain controllers, OS risk, SPNs, and delegation exposure.'

    $properties = @(
        'distinguishedName',
        'objectSid',
        'sAMAccountName',
        'cn',
        'dNSHostName',
        'description',
        'operatingSystem',
        'operatingSystemVersion',
        'operatingSystemServicePack',
        'servicePrincipalName',
        'memberOf',
        'primaryGroupID',
        'userAccountControl',
        'lastLogonTimestamp',
        'pwdLastSet',
        'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity',
        'whenCreated',
        'whenChanged'
    )

    $results = Search-Ldap -Filter '(&(objectCategory=computer)(objectClass=computer)(samAccountType=805306369))' -Properties $properties
    $computers = New-Object System.Collections.ArrayList

    foreach ($result in $results) {
        $uac = [int](Get-LdapProperty -Result $result -Name 'userAccountControl')
        $spns = Get-LdapPropertyList -Result $result -Name 'servicePrincipalName'
        $delegateTo = Get-LdapPropertyList -Result $result -Name 'msDS-AllowedToDelegateTo'
        $rbcd = Get-LdapProperty -Result $result -Name 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $os = [string](Get-LdapProperty -Result $result -Name 'operatingSystem')

        $computer = [pscustomobject]@{
            ObjectType = 'Computer'
            DistinguishedName = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
            ObjectSid = Convert-LdapSid -Value (Get-LdapProperty -Result $result -Name 'objectSid')
            SamAccountName = [string](Get-LdapProperty -Result $result -Name 'sAMAccountName')
            Name = [string](Get-LdapProperty -Result $result -Name 'cn')
            DnsHostName = [string](Get-LdapProperty -Result $result -Name 'dNSHostName')
            Description = [string](Get-LdapProperty -Result $result -Name 'description')
            OperatingSystem = $os
            OperatingSystemVersion = [string](Get-LdapProperty -Result $result -Name 'operatingSystemVersion')
            OperatingSystemServicePack = [string](Get-LdapProperty -Result $result -Name 'operatingSystemServicePack')
            IsOutdatedOS = (Test-OutdatedOperatingSystem -OperatingSystem $os)
            UserAccountControl = $uac
            UacFlags = Get-UacFlagNames -UserAccountControl $uac
            IsDisabled = (Test-UacFlag -UserAccountControl $uac -Flag 0x00000002)
            IsDomainController = ((Test-UacFlag -UserAccountControl $uac -Flag 0x00002000) -or ([string](Get-LdapProperty -Result $result -Name 'primaryGroupID') -eq '516'))
            PrimaryGroupID = [string](Get-LdapProperty -Result $result -Name 'primaryGroupID')
            ServicePrincipalNames = $spns
            HasSpns = ($spns.Count -gt 0)
            MemberOf = Get-LdapPropertyList -Result $result -Name 'memberOf'
            EffectiveGroupDns = @()
            EffectiveGroupNames = @()
            LastLogonTimestamp = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'lastLogonTimestamp')
            PwdLastSet = Convert-FileTime -Value (Get-LdapProperty -Result $result -Name 'pwdLastSet')
            UnconstrainedDelegation = (Test-UacFlag -UserAccountControl $uac -Flag 0x00080000)
            ConstrainedDelegation = ($delegateTo.Count -gt 0)
            ProtocolTransition = (Test-UacFlag -UserAccountControl $uac -Flag 0x01000000)
            DelegatesTo = $delegateTo
            ResourceBasedConstrainedDelegation = ($null -ne $rbcd)
            LateralMovementServices = @($spns | Where-Object { $_ -match '^(MSSQLSvc|HTTP|WSMAN|TERMSRV|CIFS|HOST|RPCSS)/' })
            WhenCreated = [string](Get-LdapProperty -Result $result -Name 'whenCreated')
            WhenChanged = [string](Get-LdapProperty -Result $result -Name 'whenChanged')
        }

        [void]$computers.Add($computer)
    }

    return @($computers)
}

function Get-GPLinksFromString {
    param([string]$GPLink)

    $links = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($GPLink)) {
        return @()
    }

    $matches = [regex]::Matches($GPLink, '\[LDAP://(?<dn>[^;\]]+);(?<options>\d+)\]', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($match in $matches) {
        $options = [int]$match.Groups['options'].Value
        [void]$links.Add([pscustomobject]@{
                GpoDistinguishedName = $match.Groups['dn'].Value
                Options = $options
                LinkDisabled = (($options -band 1) -eq 1)
                Enforced = (($options -band 2) -eq 2)
            })
    }

    return @($links)
}

function Get-GpoScriptInventory {
    param([string]$GpcFileSysPath)

    $scripts = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($GpcFileSysPath) -or -not (Test-Path -LiteralPath $GpcFileSysPath)) {
        return @()
    }

    $scriptLocations = @(
        @{ Type = 'MachineStartup'; Path = 'Machine\Scripts\Startup' },
        @{ Type = 'MachineShutdown'; Path = 'Machine\Scripts\Shutdown' },
        @{ Type = 'UserLogon'; Path = 'User\Scripts\Logon' },
        @{ Type = 'UserLogoff'; Path = 'User\Scripts\Logoff' }
    )

    foreach ($location in $scriptLocations) {
        $fullPath = Join-Path $GpcFileSysPath $location.Path
        if (Test-Path -LiteralPath $fullPath) {
            try {
                Get-ChildItem -LiteralPath $fullPath -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [void]$scripts.Add([pscustomobject]@{
                            Type = $location.Type
                            Name = $_.Name
                            Path = $_.FullName
                            Length = $_.Length
                            LastWriteTime = $_.LastWriteTime
                        })
                }
            }
            catch {
                Write-Status -Message ("Unable to inspect GPO scripts at {0}: {1}" -f $fullPath, $_.Exception.Message) -Color Yellow
            }
        }
    }

    return @($scripts)
}

function Get-GpoCPasswordFiles {
    param([string]$GpcFileSysPath)

    $hits = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($GpcFileSysPath) -or -not (Test-Path -LiteralPath $GpcFileSysPath)) {
        return @()
    }

    try {
        Get-ChildItem -LiteralPath $GpcFileSysPath -Recurse -Filter '*.xml' -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = [System.IO.File]::ReadAllText($_.FullName)
                if ($content -match 'cpassword\s*=') {
                    [void]$hits.Add($_.FullName)
                }
            }
            catch {
            }
        }
    }
    catch {
        Write-Status -Message ("Unable to inspect GPP XML under {0}: {1}" -f $GpcFileSysPath, $_.Exception.Message) -Color Yellow
    }

    return @($hits)
}

function Get-ADGposAdvanced {
    if ($SkipGpo) {
        return @()
    }

    Write-Status -Message 'Collecting GPO containers, OU links, scripts, SYSVOL indicators, and abuse inputs.'

    $gpoProperties = @(
        'distinguishedName',
        'name',
        'displayName',
        'gPCFileSysPath',
        'gPCMachineExtensionNames',
        'gPCUserExtensionNames',
        'gPCFunctionalityVersion',
        'flags',
        'versionNumber',
        'whenCreated',
        'whenChanged'
    )

    $linkProperties = @(
        'distinguishedName',
        'name',
        'ou',
        'canonicalName',
        'gPLink',
        'gPOptions'
    )

    $linkResults = Search-Ldap -Filter '(gPLink=*)' -Properties $linkProperties
    $linkMap = @{}
    foreach ($result in $linkResults) {
        $targetDn = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
        $targetName = [string](Get-LdapProperty -Result $result -Name 'name')
        $targetCanonicalName = [string](Get-LdapProperty -Result $result -Name 'canonicalName')
        $gpOptions = [string](Get-LdapProperty -Result $result -Name 'gPOptions')
        $links = Get-GPLinksFromString -GPLink ([string](Get-LdapProperty -Result $result -Name 'gPLink'))
        foreach ($link in $links) {
            $key = $link.GpoDistinguishedName.ToLowerInvariant()
            if (-not $linkMap.ContainsKey($key)) {
                $linkMap[$key] = New-Object System.Collections.ArrayList
            }
            [void]$linkMap[$key].Add([pscustomobject]@{
                    TargetDistinguishedName = $targetDn
                    TargetName = $targetName
                    TargetCanonicalName = $targetCanonicalName
                    LinkDisabled = $link.LinkDisabled
                    Enforced = $link.Enforced
                    Options = $link.Options
                    GPOptions = $gpOptions
                })
        }
    }

    $gpoResults = Search-Ldap -Filter '(&(objectCategory=groupPolicyContainer)(objectClass=groupPolicyContainer))' -Properties $gpoProperties
    $gpos = New-Object System.Collections.ArrayList

    foreach ($result in $gpoResults) {
        $dn = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
        $gpcPath = [string](Get-LdapProperty -Result $result -Name 'gPCFileSysPath')
        $links = @()
        $key = $dn.ToLowerInvariant()
        if ($linkMap.ContainsKey($key)) {
            $links = @($linkMap[$key])
        }

        $scripts = @()
        $cpasswordFiles = @()
        if (-not $SkipSysvolScan) {
            $scripts = Get-GpoScriptInventory -GpcFileSysPath $gpcPath
            $cpasswordFiles = Get-GpoCPasswordFiles -GpcFileSysPath $gpcPath
        }

        $gpo = [pscustomobject]@{
            ObjectType = 'GPO'
            DistinguishedName = $dn
            GuidName = [string](Get-LdapProperty -Result $result -Name 'name')
            DisplayName = [string](Get-LdapProperty -Result $result -Name 'displayName')
            GpcFileSysPath = $gpcPath
            MachineExtensions = Get-LdapPropertyList -Result $result -Name 'gPCMachineExtensionNames'
            UserExtensions = Get-LdapPropertyList -Result $result -Name 'gPCUserExtensionNames'
            FunctionalityVersion = [string](Get-LdapProperty -Result $result -Name 'gPCFunctionalityVersion')
            Flags = [string](Get-LdapProperty -Result $result -Name 'flags')
            VersionNumber = [string](Get-LdapProperty -Result $result -Name 'versionNumber')
            Links = $links
            LinkCount = $links.Count
            LinkedTargets = @($links | ForEach-Object { $_.TargetCanonicalName })
            Scripts = $scripts
            ScriptCount = $scripts.Count
            CPasswordFiles = $cpasswordFiles
            CPasswordFileCount = $cpasswordFiles.Count
            WhenCreated = [string](Get-LdapProperty -Result $result -Name 'whenCreated')
            WhenChanged = [string](Get-LdapProperty -Result $result -Name 'whenChanged')
        }

        [void]$gpos.Add($gpo)
    }

    return @($gpos)
}

function Convert-TrustDirection {
    param([object]$Value)

    switch ([int]$Value) {
        0 { return 'Disabled' }
        1 { return 'Inbound' }
        2 { return 'Outbound' }
        3 { return 'Bidirectional' }
        default { return [string]$Value }
    }
}

function Convert-TrustType {
    param([object]$Value)

    switch ([int]$Value) {
        1 { return 'Downlevel' }
        2 { return 'Uplevel' }
        3 { return 'MIT Kerberos' }
        4 { return 'DCE' }
        default { return [string]$Value }
    }
}

function Get-TrustAttributeFlags {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    $attributes = [int]$Value
    $flags = @(
        @{ Name = 'NON_TRANSITIVE'; Value = 0x00000001 },
        @{ Name = 'UPLEVEL_ONLY'; Value = 0x00000002 },
        @{ Name = 'QUARANTINED_DOMAIN_SID_FILTERING'; Value = 0x00000004 },
        @{ Name = 'FOREST_TRANSITIVE'; Value = 0x00000008 },
        @{ Name = 'CROSS_ORGANIZATION'; Value = 0x00000010 },
        @{ Name = 'WITHIN_FOREST'; Value = 0x00000020 },
        @{ Name = 'TREAT_AS_EXTERNAL'; Value = 0x00000040 },
        @{ Name = 'USES_RC4_ENCRYPTION'; Value = 0x00000080 },
        @{ Name = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'; Value = 0x00000200 },
        @{ Name = 'PIM_TRUST'; Value = 0x00000400 }
    )

    return @($flags | Where-Object { ($attributes -band $_.Value) -ne 0 } | ForEach-Object { $_.Name })
}

function Get-ADTrustsAdvanced {
    if ($SkipTrust) {
        return @()
    }

    Write-Status -Message 'Collecting domain, forest, external, and transitive trust relationships.'

    $trusts = New-Object System.Collections.ArrayList
    $systemDn = "CN=System,$($script:ADContext.DistinguishedName)"
    $systemEntry = New-Object System.DirectoryServices.DirectoryEntry((New-LdapPath -DistinguishedName $systemDn))

    try {
        $properties = @(
            'distinguishedName',
            'cn',
            'trustPartner',
            'flatName',
            'trustDirection',
            'trustType',
            'trustAttributes',
            'securityIdentifier',
            'whenCreated',
            'whenChanged'
        )

        $results = Search-Ldap -Filter '(objectClass=trustedDomain)' -Properties $properties -SearchRoot $systemEntry
        foreach ($result in $results) {
            $attrs = Get-LdapProperty -Result $result -Name 'trustAttributes'
            $trust = [pscustomobject]@{
                ObjectType = 'Trust'
                DistinguishedName = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
                Name = [string](Get-LdapProperty -Result $result -Name 'cn')
                TrustPartner = [string](Get-LdapProperty -Result $result -Name 'trustPartner')
                FlatName = [string](Get-LdapProperty -Result $result -Name 'flatName')
                Direction = Convert-TrustDirection -Value (Get-LdapProperty -Result $result -Name 'trustDirection')
                Type = Convert-TrustType -Value (Get-LdapProperty -Result $result -Name 'trustType')
                TrustAttributes = [string]$attrs
                AttributeFlags = Get-TrustAttributeFlags -Value $attrs
                SecurityIdentifier = Convert-LdapSid -Value (Get-LdapProperty -Result $result -Name 'securityIdentifier')
                WhenCreated = [string](Get-LdapProperty -Result $result -Name 'whenCreated')
                WhenChanged = [string](Get-LdapProperty -Result $result -Name 'whenChanged')
            }

            [void]$trusts.Add($trust)
        }
    }
    finally {
        $systemEntry.Dispose()
    }

    return @($trusts)
}

function Test-TrustedAclPrincipal {
    param(
        [string]$AccountName,
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($AccountName)) {
        $AccountName = ''
    }

    $trustedPatterns = @(
        'NT AUTHORITY\SYSTEM',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'BUILTIN\Administrators',
        'CREATOR OWNER',
        'SELF'
    )

    foreach ($pattern in $trustedPatterns) {
        if ($AccountName -ieq $pattern) {
            return $true
        }
    }

    if ($AccountName -match '\\(Domain Admins|Enterprise Admins|Schema Admins)$') {
        return $true
    }

    if ($Sid -in @('S-1-5-18', 'S-1-5-10')) {
        return $true
    }

    if ($Sid -match '-(512|518|519|544)$') {
        return $true
    }

    return $false
}

function Get-DangerousAclRules {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DistinguishedName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ObjectType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ObjectName
    )

    $findings = New-Object System.Collections.ArrayList
    $entry = $null

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry((New-LdapPath -DistinguishedName $DistinguishedName))
        $entry.PSBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $acl = $entry.PSBase.ObjectSecurity
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            $rights = $rule.ActiveDirectoryRights
            $dangerousRights = New-Object System.Collections.ArrayList

            if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0) { [void]$dangerousRights.Add('GenericAll') }
            if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -ne 0) { [void]$dangerousRights.Add('GenericWrite') }
            if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -ne 0) { [void]$dangerousRights.Add('WriteDACL') }
            if (($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0) { [void]$dangerousRights.Add('WriteOwner') }

            if ($dangerousRights.Count -eq 0) {
                continue
            }

            $sid = [string]$rule.IdentityReference.Value
            $accountName = Resolve-SidName -Sid $sid
            if (Test-TrustedAclPrincipal -AccountName $accountName -Sid $sid) {
                continue
            }

            $risk = 'Critical'
            if ($rule.IsInherited -and $ObjectType -notin @('GPO', 'Group', 'User')) {
                $risk = 'Medium'
            }

            [void]$findings.Add([pscustomobject]@{
                    Risk = $risk
                    ObjectType = $ObjectType
                    ObjectName = $ObjectName
                    DistinguishedName = $DistinguishedName
                    Principal = $accountName
                    PrincipalSid = $sid
                    Rights = @($dangerousRights)
                    IsInherited = $rule.IsInherited
                    ObjectAceType = [string]$rule.ObjectType
                    InheritedObjectAceType = [string]$rule.InheritedObjectType
                })
        }
    }
    catch {
        Write-Status -Message ("ACL scan failed for {0}: {1}" -f $ObjectName, $_.Exception.Message) -Color Yellow
    }
    finally {
        if ($null -ne $entry) {
            $entry.Dispose()
        }
    }

    return @($findings)
}

function Invoke-AclAnalysis {
    param(
        [object[]]$Users,
        [object[]]$Groups,
        [object[]]$Computers,
        [object[]]$Gpos
    )

    if ($AclScope -eq 'None') {
        return @()
    }

    Write-Status -Message ("Scanning ACLs for takeover rights. Scope={0}; MaxObjects={1}." -f $AclScope, $MaxAclObjects)

    $targets = New-Object System.Collections.ArrayList
    [void]$targets.Add([pscustomobject]@{ DistinguishedName = $script:ADContext.DistinguishedName; ObjectType = 'Domain'; Name = $script:ADContext.DnsRoot })

    if ($AclScope -eq 'All') {
        foreach ($item in @($Users + $Groups + $Computers + $Gpos)) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace($item.DistinguishedName)) {
                $display = $item.Name
                if ([string]::IsNullOrWhiteSpace($display) -and $item.PSObject.Properties.Name -contains 'SamAccountName') {
                    $display = $item.SamAccountName
                }
                if ([string]::IsNullOrWhiteSpace($display) -and $item.PSObject.Properties.Name -contains 'DisplayName') {
                    $display = $item.DisplayName
                }
                [void]$targets.Add([pscustomobject]@{ DistinguishedName = $item.DistinguishedName; ObjectType = $item.ObjectType; Name = $display })
            }
        }
    }
    else {
        foreach ($item in @($Groups | Where-Object { $_.IsDangerousGroup -or $_.AdminCount })) {
            [void]$targets.Add([pscustomobject]@{ DistinguishedName = $item.DistinguishedName; ObjectType = 'Group'; Name = $item.SamAccountName })
        }
        foreach ($item in @($Users | Where-Object { $_.AdminCount -or $_.IsKerberoastable -or $_.IsAsRepRoastable -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation })) {
            [void]$targets.Add([pscustomobject]@{ DistinguishedName = $item.DistinguishedName; ObjectType = 'User'; Name = $item.SamAccountName })
        }
        foreach ($item in @($Computers | Where-Object { $_.IsDomainController -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation -or $_.ResourceBasedConstrainedDelegation })) {
            [void]$targets.Add([pscustomobject]@{ DistinguishedName = $item.DistinguishedName; ObjectType = 'Computer'; Name = $item.SamAccountName })
        }
        foreach ($gpo in @($Gpos)) {
            [void]$targets.Add([pscustomobject]@{ DistinguishedName = $gpo.DistinguishedName; ObjectType = 'GPO'; Name = $gpo.DisplayName })
            foreach ($link in $gpo.Links) {
                if (-not [string]::IsNullOrWhiteSpace($link.TargetDistinguishedName)) {
                    [void]$targets.Add([pscustomobject]@{ DistinguishedName = $link.TargetDistinguishedName; ObjectType = 'GpoLinkedContainer'; Name = $link.TargetCanonicalName })
                }
            }
        }
    }

    $uniqueTargets = @{}
    foreach ($target in $targets) {
        if (-not [string]::IsNullOrWhiteSpace($target.DistinguishedName) -and -not $uniqueTargets.ContainsKey($target.DistinguishedName)) {
            $uniqueTargets[$target.DistinguishedName] = $target
        }
    }

    $aclFindings = New-Object System.Collections.ArrayList
    $targetList = @($uniqueTargets.Values | Select-Object -First $MaxAclObjects)
    foreach ($target in $targetList) {
        $dangerousRules = Get-DangerousAclRules -DistinguishedName $target.DistinguishedName -ObjectType $target.ObjectType -ObjectName $target.Name
        foreach ($rule in $dangerousRules) {
            [void]$aclFindings.Add($rule)
            Add-Finding -Risk $rule.Risk `
                -Category 'ACL / Permissions' `
                -ObjectType $rule.ObjectType `
                -Name $rule.ObjectName `
                -Target $rule.Principal `
                -DistinguishedName $rule.DistinguishedName `
                -AttackVector 'Object takeover via dangerous ACE' `
                -Evidence ("{0} has {1} on {2}. Inherited={3}" -f $rule.Principal, (($rule.Rights) -join ','), $rule.ObjectName, $rule.IsInherited) `
                -Impact 'A non-standard principal can modify ownership, DACL, or object attributes and may escalate privileges.' `
                -Recommendation 'Remove non-administrative takeover rights; review AdminSDHolder, delegated OU permissions, and GPO delegation.' `
                -Tags @('ACL', 'GenericAll', 'GenericWrite', 'WriteDACL', 'WriteOwner') | Out-Null

            Add-RelationshipEdge -Source $rule.Principal -Relationship ("Can{0}" -f (($rule.Rights) -join '+')) -Target $rule.ObjectName -Risk $rule.Risk -Evidence 'Dangerous Active Directory ACE' | Out-Null
        }
    }

    return @($aclFindings)
}

function Invoke-RiskAnalysis {
    param(
        [object[]]$Users,
        [object[]]$Groups,
        [object[]]$Computers,
        [object[]]$Gpos,
        [object[]]$Trusts
    )

    Write-Status -Message 'Running risk classification engine and attack path inference.'

    $objectsByDn = @{}
    $groupsByDn = @{}
    foreach ($group in $Groups) {
        $objectsByDn[$group.DistinguishedName] = $group
        $groupsByDn[$group.DistinguishedName] = $group
    }
    foreach ($user in $Users) {
        $objectsByDn[$user.DistinguishedName] = $user
    }
    foreach ($computer in $Computers) {
        $objectsByDn[$computer.DistinguishedName] = $computer
    }

    foreach ($group in $Groups) {
        $nestedMembers = Get-RecursiveGroupMembers -GroupDn $group.DistinguishedName -GroupsByDn $groupsByDn -DepthLimit $MaxGroupDepth
        $group.NestedMembers = @($nestedMembers | ForEach-Object { Get-PrincipalDisplayName -DistinguishedName $_ -ObjectByDn $objectsByDn })
        $group.NestedMemberCount = $nestedMembers.Count
    }

    foreach ($user in $Users) {
        $effectiveGroupDns = Get-EffectiveGroupDns -DirectMemberOf $user.MemberOf -GroupsByDn $groupsByDn -DepthLimit $MaxGroupDepth
        $effectiveGroupNames = @($effectiveGroupDns | ForEach-Object {
                if ($groupsByDn.ContainsKey($_)) { $groupsByDn[$_].SamAccountName } else { $_ }
            })
        $user.EffectiveGroupDns = $effectiveGroupDns
        $user.EffectiveGroupNames = $effectiveGroupNames
        $privilegedGroups = @($effectiveGroupNames | Where-Object { Test-CriticalGroup -GroupName $_ })
        if ($user.AdminCount -or $privilegedGroups.Count -gt 0) {
            $user.IsPrivileged = $true
            $user.PrivilegeReason = (($privilegedGroups + @($(if ($user.AdminCount) { 'AdminCount=1' }))) | Where-Object { $_ }) -join '; '
        }
    }

    foreach ($computer in $Computers) {
        $effectiveGroupDns = Get-EffectiveGroupDns -DirectMemberOf $computer.MemberOf -GroupsByDn $groupsByDn -DepthLimit $MaxGroupDepth
        $computer.EffectiveGroupDns = $effectiveGroupDns
        $computer.EffectiveGroupNames = @($effectiveGroupDns | ForEach-Object {
                if ($groupsByDn.ContainsKey($_)) { $groupsByDn[$_].SamAccountName } else { $_ }
            })
    }

    foreach ($user in $Users) {
        if ($user.IsKerberoastable) {
            Add-Finding -Risk 'Critical' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Kerberoasting' -Evidence ("SPNs: {0}" -f (($user.ServicePrincipalNames | Select-Object -First 8) -join '; ')) -Impact 'An attacker can request service tickets for this account and perform offline password cracking.' -Recommendation 'Move services to gMSA/MSA where possible, enforce long random passwords, reduce privileges, and monitor abnormal TGS requests.' -Tags @('Kerberoast', 'SPN') | Out-Null
            Add-RelationshipEdge -Source $user.SamAccountName -Relationship 'HasSPN' -Target (($user.ServicePrincipalNames | Select-Object -First 3) -join '; ') -Risk 'Critical' -Evidence 'servicePrincipalName populated on user object' | Out-Null
        }

        if ($user.IsAsRepRoastable) {
            Add-Finding -Risk 'Critical' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'AS-REP Roasting' -Evidence 'DONT_REQ_PREAUTH is set.' -Impact 'An attacker can request an AS-REP for offline password cracking without pre-authentication.' -Recommendation 'Enable Kerberos pre-authentication and investigate why the flag was set.' -Tags @('ASREP', 'DONT_REQ_PREAUTH') | Out-Null
        }

        if ($user.IsPrivileged) {
            Add-Finding -Risk 'Critical' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Privileged account exposure' -Evidence $user.PrivilegeReason -Impact 'Compromise of this account may provide direct or nested administrative access.' -Recommendation 'Apply tiering, PAWs, MFA where applicable, just-in-time administration, and remove unnecessary memberships.' -Tags @('Privileged', 'AdminCount') | Out-Null
            foreach ($groupName in $user.EffectiveGroupNames | Where-Object { Test-CriticalGroup -GroupName $_ }) {
                Add-RelationshipEdge -Source $user.SamAccountName -Relationship 'MemberOf' -Target $groupName -Risk 'Critical' -Evidence 'Effective nested membership in critical group' | Out-Null
            }
        }

        if ($user.PasswordNeverExpires -and -not $user.IsDisabled) {
            Add-Finding -Risk 'Medium' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Credential persistence' -Evidence 'DONT_EXPIRE_PASSWORD is set.' -Impact 'Long-lived credentials increase the value of credential theft and offline cracking.' -Recommendation 'Remove password-never-expires unless technically required; prefer managed service accounts for services.' -Tags @('PasswordPolicy') | Out-Null
        }

        if ($user.PasswordNotRequired -and -not $user.IsDisabled) {
            Add-Finding -Risk 'Critical' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Weak account configuration' -Evidence 'PASSWD_NOTREQD is set.' -Impact 'Account may be misconfigured with weak or missing password controls.' -Recommendation 'Clear PASSWD_NOTREQD, reset the account password, and validate account creation processes.' -Tags @('PasswordPolicy') | Out-Null
        }

        if (($user.UnconstrainedDelegation -or $user.ConstrainedDelegation -or $user.ProtocolTransition -or $user.ResourceBasedConstrainedDelegation) -and -not $user.IsDisabled) {
            $delegationTypes = @()
            if ($user.UnconstrainedDelegation) { $delegationTypes += 'Unconstrained' }
            if ($user.ConstrainedDelegation) { $delegationTypes += 'Constrained' }
            if ($user.ProtocolTransition) { $delegationTypes += 'ProtocolTransition' }
            if ($user.ResourceBasedConstrainedDelegation) { $delegationTypes += 'ResourceBased' }

            Add-Finding -Risk 'Critical' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Delegation abuse' -Evidence ("Delegation: {0}. Targets: {1}" -f (($delegationTypes) -join ','), (($user.DelegatesTo | Select-Object -First 8) -join '; ')) -Impact 'Delegation can allow impersonation paths if the account is compromised or configured too broadly.' -Recommendation 'Remove unconstrained delegation; constrain delegation to exact services; mark privileged users as sensitive and cannot be delegated.' -Tags @('Delegation') | Out-Null
            foreach ($target in $user.DelegatesTo) {
                Add-RelationshipEdge -Source $user.SamAccountName -Relationship 'DelegatesTo' -Target $target -Risk 'Critical' -Evidence 'msDS-AllowedToDelegateTo' | Out-Null
            }
        }

        if ($user.IsDisabled) {
            Add-Finding -Risk 'Low' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Account hygiene' -Evidence 'ACCOUNTDISABLE is set.' -Impact 'Disabled accounts should still be monitored for stale privilege and delegated ACL residue.' -Recommendation 'Review disabled privileged/service accounts and remove unnecessary group memberships and SPNs.' -Tags @('Hygiene') | Out-Null
        }

        if ($null -ne $user.LastLogonTimestamp -and $user.LastLogonTimestamp -lt (Get-Date).AddDays(-1 * $StaleDays) -and -not $user.IsDisabled) {
            Add-Finding -Risk 'Medium' -Category 'Users' -ObjectType 'User' -Name $user.SamAccountName -DistinguishedName $user.DistinguishedName -AttackVector 'Stale active account' -Evidence ("LastLogonTimestamp: {0}" -f $user.LastLogonTimestamp) -Impact 'Unused active accounts are attractive persistence and credential theft targets.' -Recommendation 'Disable or remove stale accounts after business validation.' -Tags @('Hygiene', 'Stale') | Out-Null
        }
    }

    foreach ($group in $Groups) {
        if ($group.IsDangerousGroup -and $group.NestedMemberCount -gt 0) {
            $risk = 'Medium'
            if ($group.IsCriticalGroup) {
                $risk = 'Critical'
            }

            Add-Finding -Risk $risk -Category 'Groups' -ObjectType 'Group' -Name $group.SamAccountName -DistinguishedName $group.DistinguishedName -AttackVector 'Dangerous group membership' -Evidence ("Direct members: {0}; nested members: {1}" -f $group.MemberCount, $group.NestedMemberCount) -Impact 'Members may gain privileged administration, lateral movement, or sensitive directory read capabilities.' -Recommendation 'Minimize membership, remove nested custom groups where possible, and require privileged access workflow.' -Tags @('Groups', 'Privilege') | Out-Null
        }

        if (-not $group.IsDefaultGroup -and $group.MemberCount -ge $LargeGroupThreshold) {
            Add-Finding -Risk 'Medium' -Category 'Groups' -ObjectType 'Group' -Name $group.SamAccountName -DistinguishedName $group.DistinguishedName -AttackVector 'Large custom group' -Evidence ("Custom group member count: {0}" -f $group.MemberCount) -Impact 'Large custom groups often become broad authorization principals and can hide unexpected privilege.' -Recommendation 'Review authorization purpose, owners, nested groups, and remove unused members.' -Tags @('Groups', 'Custom') | Out-Null
        }

        foreach ($memberDn in $group.Members | Where-Object { $groupsByDn.ContainsKey($_) }) {
            $memberName = $groupsByDn[$memberDn].SamAccountName
            if ($group.IsDangerousGroup) {
                Add-RelationshipEdge -Source $memberName -Relationship 'NestedInto' -Target $group.SamAccountName -Risk ($(if ($group.IsCriticalGroup) { 'Critical' } else { 'Medium' })) -Evidence 'Nested group membership' | Out-Null
            }
        }
    }

    foreach ($computer in $Computers) {
        if ($computer.IsDomainController) {
            Add-Finding -Risk 'Low' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Domain controller inventory' -Evidence ("DNS: {0}; OS: {1}" -f $computer.DnsHostName, $computer.OperatingSystem) -Impact 'Domain controllers are crown-jewel assets and should be isolated and monitored.' -Recommendation 'Validate DC patching, backup, tiering, audit policy, and delegation posture.' -Tags @('DomainController') | Out-Null
        }

        if ($computer.IsOutdatedOS -and -not $computer.IsDisabled) {
            Add-Finding -Risk 'Medium' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Outdated operating system' -Evidence ("OS: {0} {1}" -f $computer.OperatingSystem, $computer.OperatingSystemVersion) -Impact 'Outdated systems frequently lack modern hardening and security updates.' -Recommendation 'Patch, upgrade, isolate, or retire legacy systems; prioritize systems with SPNs or delegation.' -Tags @('LegacyOS') | Out-Null
        }

        if ($computer.UnconstrainedDelegation -and -not $computer.IsDisabled) {
            Add-Finding -Risk 'Critical' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Unconstrained delegation' -Evidence 'TRUSTED_FOR_DELEGATION is set.' -Impact 'Compromise of this host can expose delegated Kerberos tickets for users authenticating to it.' -Recommendation 'Remove unconstrained delegation; migrate to constrained/resource-based delegation and protect privileged accounts.' -Tags @('Delegation', 'Computer') | Out-Null
            Add-RelationshipEdge -Source $computer.SamAccountName -Relationship 'UnconstrainedDelegation' -Target $script:ADContext.DnsRoot -Risk 'Critical' -Evidence 'TRUSTED_FOR_DELEGATION' | Out-Null
        }

        if (($computer.ConstrainedDelegation -or $computer.ProtocolTransition -or $computer.ResourceBasedConstrainedDelegation) -and -not $computer.IsDisabled) {
            Add-Finding -Risk 'Critical' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Constrained/RBCD delegation' -Evidence ("Targets: {0}" -f (($computer.DelegatesTo | Select-Object -First 8) -join '; ')) -Impact 'Delegation relationships may allow service impersonation if the computer account is compromised.' -Recommendation 'Validate every delegation target and remove protocol transition unless required.' -Tags @('Delegation', 'RBCD') | Out-Null
            foreach ($target in $computer.DelegatesTo) {
                Add-RelationshipEdge -Source $computer.SamAccountName -Relationship 'DelegatesTo' -Target $target -Risk 'Critical' -Evidence 'msDS-AllowedToDelegateTo' | Out-Null
            }
        }

        if ($computer.LateralMovementServices.Count -gt 0 -and -not $computer.IsDisabled) {
            Add-Finding -Risk 'Medium' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Lateral movement service surface' -Evidence (($computer.LateralMovementServices | Select-Object -First 8) -join '; ') -Impact 'Exposed service SPNs identify reachable protocols and service targets for lateral movement planning.' -Recommendation 'Restrict administration protocols, monitor service ticket requests, and validate service ownership.' -Tags @('SPN', 'LateralMovement') | Out-Null
        }

        if ($null -ne $computer.LastLogonTimestamp -and $computer.LastLogonTimestamp -lt (Get-Date).AddDays(-1 * $StaleDays) -and -not $computer.IsDisabled) {
            Add-Finding -Risk 'Medium' -Category 'Machines' -ObjectType 'Computer' -Name $computer.SamAccountName -DistinguishedName $computer.DistinguishedName -AttackVector 'Stale computer account' -Evidence ("LastLogonTimestamp: {0}" -f $computer.LastLogonTimestamp) -Impact 'Stale computer accounts can retain SPNs, delegation, and local admin assumptions.' -Recommendation 'Disable or remove stale computer accounts after owner validation.' -Tags @('Hygiene', 'Stale') | Out-Null
        }
    }

    foreach ($gpo in $Gpos) {
        foreach ($link in $gpo.Links) {
            Add-RelationshipEdge -Source $gpo.DisplayName -Relationship 'LinkedTo' -Target $link.TargetCanonicalName -Risk 'Info' -Evidence 'gPLink relationship' | Out-Null
        }

        if ($gpo.ScriptCount -gt 0) {
            Add-Finding -Risk 'Medium' -Category 'GPO' -ObjectType 'GPO' -Name $gpo.DisplayName -DistinguishedName $gpo.DistinguishedName -AttackVector 'GPO script execution' -Evidence ("Scripts discovered: {0}" -f $gpo.ScriptCount) -Impact 'Startup, shutdown, logon, or logoff scripts can execute code across linked scopes.' -Recommendation 'Review script content, ownership, signing, and GPO delegation; remove obsolete scripts.' -Tags @('GPO', 'Scripts') | Out-Null
        }

        if ($gpo.CPasswordFileCount -gt 0) {
            Add-Finding -Risk 'Critical' -Category 'GPO' -ObjectType 'GPO' -Name $gpo.DisplayName -DistinguishedName $gpo.DistinguishedName -AttackVector 'Group Policy Preferences cpassword exposure' -Evidence (($gpo.CPasswordFiles | Select-Object -First 5) -join '; ') -Impact 'Legacy GPP cpassword values can expose recoverable credentials from SYSVOL.' -Recommendation 'Remove cpassword XML, rotate exposed credentials, and audit SYSVOL history and backups.' -Tags @('GPP', 'cpassword', 'SYSVOL') | Out-Null
        }

        if ($gpo.LinkCount -eq 0) {
            Add-Finding -Risk 'Low' -Category 'GPO' -ObjectType 'GPO' -Name $gpo.DisplayName -DistinguishedName $gpo.DistinguishedName -AttackVector 'Unlinked GPO' -Evidence 'No gPLink references were discovered in the domain naming context.' -Impact 'Unlinked GPOs can retain risky settings or delegation and may later be linked unintentionally.' -Recommendation 'Review unlinked GPOs and delete or lock down stale policy objects.' -Tags @('GPO', 'Hygiene') | Out-Null
        }
    }

    foreach ($trust in $Trusts) {
        $risk = 'Info'
        if ($trust.Direction -eq 'Bidirectional') {
            $risk = 'Medium'
        }

        Add-Finding -Risk $risk -Category 'Trusts' -ObjectType 'Trust' -Name $trust.TrustPartner -DistinguishedName $trust.DistinguishedName -AttackVector 'Trust relationship' -Evidence ("Direction={0}; Type={1}; Attributes={2}" -f $trust.Direction, $trust.Type, (($trust.AttributeFlags) -join ',')) -Impact 'Trusts extend authentication and authorization paths across security boundaries.' -Recommendation 'Validate trust direction, selective authentication, SID filtering, and cross-domain privileged memberships.' -Tags @('Trusts') | Out-Null
        Add-RelationshipEdge -Source $script:ADContext.DnsRoot -Relationship ("Trusts{0}" -f $trust.Direction) -Target $trust.TrustPartner -Risk $risk -Evidence (($trust.AttributeFlags) -join ',') | Out-Null

        if (($trust.AttributeFlags -notcontains 'QUARANTINED_DOMAIN_SID_FILTERING') -and ($trust.AttributeFlags -contains 'TREAT_AS_EXTERNAL' -or $trust.Type -ne 'Uplevel')) {
            Add-Finding -Risk 'Medium' -Category 'Trusts' -ObjectType 'Trust' -Name $trust.TrustPartner -DistinguishedName $trust.DistinguishedName -AttackVector 'Trust filtering review' -Evidence 'SID filtering quarantine flag was not observed on this trustedDomain object.' -Impact 'Trusts without expected filtering controls may increase cross-boundary abuse risk.' -Recommendation 'Confirm SID filtering and selective authentication settings for external or forest trusts.' -Tags @('Trusts', 'SIDFiltering') | Out-Null
        }
    }
}

function Invoke-AttackPathAnalysis {
    param(
        [object[]]$Users,
        [object[]]$Groups,
        [object[]]$Computers,
        [object[]]$Gpos,
        [object[]]$AclFindings
    )

    Write-Status -Message 'Building BloodHound-like attack path chains and relationship map.'

    foreach ($user in $Users | Where-Object { $_.IsKerberoastable -and $_.IsPrivileged }) {
        Add-AttackPath -Risk 'Critical' -Name 'Kerberoast to privileged account' -Start $user.SamAccountName -Steps @(
            'Request service ticket for exposed SPN',
            'Perform offline password attack against the service ticket',
            'Use recovered credential for the service account',
            ("Leverage effective privilege: {0}" -f $user.PrivilegeReason)
        ) -End 'Privileged domain access' -Evidence ("SPNs: {0}" -f (($user.ServicePrincipalNames | Select-Object -First 5) -join '; ')) -Recommendation 'Remove SPN from privileged user accounts and migrate services to gMSA or least-privilege service principals.' | Out-Null
    }

    foreach ($user in $Users | Where-Object { $_.IsAsRepRoastable -and $_.IsPrivileged }) {
        Add-AttackPath -Risk 'Critical' -Name 'AS-REP roast to privileged account' -Start $user.SamAccountName -Steps @(
            'Request AS-REP without Kerberos pre-authentication',
            'Perform offline password attack against AS-REP material',
            'Use recovered credential for the target account',
            ("Leverage effective privilege: {0}" -f $user.PrivilegeReason)
        ) -End 'Privileged domain access' -Evidence 'DONT_REQ_PREAUTH on privileged account' -Recommendation 'Enable pre-authentication and rotate the account password.' | Out-Null
    }

    foreach ($computer in $Computers | Where-Object { $_.UnconstrainedDelegation -and -not $_.IsDomainController -and -not $_.IsDisabled }) {
        Add-AttackPath -Risk 'Critical' -Name 'Compromised host to delegated ticket exposure' -Start $computer.SamAccountName -Steps @(
            'Gain administrative control of the unconstrained delegation host',
            'Wait for privileged authentication to the host or coerce a legitimate connection in an authorized test',
            'Capture delegated Kerberos material present on the host',
            'Impersonate delegated identity to reachable services'
        ) -End 'Lateral movement or privilege escalation' -Evidence 'TRUSTED_FOR_DELEGATION on non-DC computer' -Recommendation 'Remove unconstrained delegation and mark privileged users as sensitive and cannot be delegated.' | Out-Null
    }

    foreach ($computer in $Computers | Where-Object { ($_.ConstrainedDelegation -or $_.ResourceBasedConstrainedDelegation) -and -not $_.IsDisabled }) {
        Add-AttackPath -Risk 'Critical' -Name 'Delegation edge to service impersonation' -Start $computer.SamAccountName -Steps @(
            'Compromise or control the delegated computer account',
            'Abuse configured delegation relationship within its allowed target set',
            ("Target services: {0}" -f (($computer.DelegatesTo | Select-Object -First 5) -join '; '))
        ) -End 'Service impersonation path' -Evidence 'Constrained or resource-based delegation configured' -Recommendation 'Restrict delegation to exact required targets and remove protocol transition where not required.' | Out-Null
    }

    foreach ($group in $Groups | Where-Object { $_.SamAccountName -eq 'DnsAdmins' -and $_.NestedMemberCount -gt 0 }) {
        Add-AttackPath -Risk 'Critical' -Name 'DnsAdmins to domain controller code execution' -Start 'DnsAdmins members' -Steps @(
            'Member has DNS server administration rights',
            'DNS service runs on domain controllers in common deployments',
            'Misuse of DNS server plugin configuration can lead to code execution on the DNS server'
        ) -End 'Domain controller compromise risk' -Evidence ("Nested members: {0}" -f (($group.NestedMembers | Select-Object -First 10) -join '; ')) -Recommendation 'Keep DnsAdmins empty or tightly controlled; monitor DNS server configuration changes.' | Out-Null
    }

    foreach ($acl in $AclFindings) {
        $steps = @(
            ("Use {0} granted to {1}" -f (($acl.Rights) -join '+'), $acl.Principal),
            ("Modify or take ownership of target {0}" -f $acl.ObjectName),
            'Chain the modified object into privilege, delegation, or policy execution'
        )

        if ($acl.ObjectType -eq 'GPO') {
            $gpo = $Gpos | Where-Object { $_.DisplayName -eq $acl.ObjectName -or $_.DistinguishedName -eq $acl.DistinguishedName } | Select-Object -First 1
            if ($null -ne $gpo -and $gpo.LinkCount -gt 0) {
                $steps += ("Affected linked scopes: {0}" -f (($gpo.LinkedTargets | Select-Object -First 5) -join '; '))
            }
        }

        Add-AttackPath -Risk $acl.Risk -Name 'Dangerous ACL to object takeover' -Start $acl.Principal -Steps $steps -End $acl.ObjectName -Evidence ("{0} on {1}" -f (($acl.Rights) -join '+'), $acl.ObjectType) -Recommendation 'Remove delegated takeover rights and validate owner/DACL inheritance.' | Out-Null
    }

    foreach ($gpo in $Gpos | Where-Object { $_.ScriptCount -gt 0 -and $_.LinkCount -gt 0 }) {
        Add-AttackPath -Risk 'Medium' -Name 'GPO script execution surface' -Start $gpo.DisplayName -Steps @(
            'GPO contains startup, shutdown, logon, or logoff script content',
            ("GPO is linked to {0} scope(s)" -f $gpo.LinkCount),
            'Compromise of GPO edit rights or script path can result in code execution across linked systems or users'
        ) -End 'Policy-driven code execution surface' -Evidence ("Scripts: {0}" -f $gpo.ScriptCount) -Recommendation 'Audit GPO delegation, sign scripts, and remove obsolete policy scripts.' | Out-Null
    }
}

function Invoke-LegacyLookup {
    param(
        [string]$Type,
        [string]$LookupName,
        [string]$LookupProperty
    )

    if ([string]::IsNullOrWhiteSpace($LookupName) -or [string]::IsNullOrWhiteSpace($LookupProperty)) {
        return $false
    }

    $filter = ''
    switch ($Type) {
        'U' { $filter = '(&(objectCategory=person)(objectClass=user)(samAccountType=805306368))' }
        'Users' { $filter = '(&(objectCategory=person)(objectClass=user)(samAccountType=805306368))' }
        'M' { $filter = '(&(objectCategory=computer)(objectClass=computer)(samAccountType=805306369))' }
        'Machines' { $filter = '(&(objectCategory=computer)(objectClass=computer)(samAccountType=805306369))' }
        'G' { $filter = '(&(objectCategory=group)(objectClass=group))' }
        'Groups' { $filter = '(&(objectCategory=group)(objectClass=group))' }
        default { $filter = '(|(&(objectCategory=person)(objectClass=user))(&(objectCategory=computer)(objectClass=computer))(&(objectCategory=group)(objectClass=group)))' }
    }

    $escaped = Escape-LdapFilterValue -Value $LookupName
    $combined = "(&$filter(|(sAMAccountName=$escaped)(cn=$escaped)(name=$escaped)))"
    $properties = @('distinguishedName', 'sAMAccountName', 'cn', 'name', $LookupProperty)
    if ($LookupProperty -eq '*') {
        $properties = @('*')
    }

    $results = Search-Ldap -Filter $combined -Properties $properties
    if ($results.Count -eq 0) {
        Write-Host "No object matched $LookupName." -ForegroundColor Yellow
        return $true
    }

    foreach ($result in $results) {
        if ($LookupProperty -eq '*') {
            $hash = [ordered]@{}
            foreach ($propertyName in $result.Properties.PropertyNames) {
                $hash[$propertyName] = ConvertTo-StringArray -Value $result.Properties[$propertyName]
            }
            [pscustomobject]$hash | Format-List
        }
        else {
            $value = Get-LdapProperty -Result $result -Name $LookupProperty
            [pscustomobject]@{
                DistinguishedName = [string](Get-LdapProperty -Result $result -Name 'distinguishedName')
                Name = [string](Get-LdapProperty -Result $result -Name 'sAMAccountName')
                Property = $LookupProperty
                Value = ConvertTo-StringArray -Value $value
            } | Format-List
        }
    }

    return $true
}

function Get-RiskSummary {
    param([object[]]$Findings)

    $summary = [ordered]@{
        Critical = @($Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
        Medium = @($Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
        Low = @($Findings | Where-Object { $_.Risk -eq 'Low' }).Count
        Info = @($Findings | Where-Object { $_.Risk -eq 'Info' }).Count
    }

    return [pscustomobject]$summary
}

function Export-ADEnumData {
    param(
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][string]$Directory
    )

    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }

    $exported = [ordered]@{}

    if (-not $NoJson) {
        $jsonPath = Join-Path $Directory 'ADEnum_Report.json'
        $Report | ConvertTo-Json -Depth 12 | Out-File -LiteralPath $jsonPath -Encoding UTF8
        $exported.Json = $jsonPath
    }

    if (-not $NoCsv) {
        $csvMap = [ordered]@{
            Users = $Report.Users
            Groups = $Report.Groups
            Computers = $Report.Computers
            GPOs = $Report.GPOs
            Trusts = $Report.Trusts
            Findings = $Report.Findings
            AttackPaths = $Report.AttackPaths
            RelationshipEdges = $Report.RelationshipEdges
            AclFindings = $Report.AclFindings
        }

        foreach ($key in $csvMap.Keys) {
            $csvPath = Join-Path $Directory ("{0}.csv" -f $key)
            Convert-ObjectForCsv -InputObject @($csvMap[$key]) | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
            $exported[$key] = $csvPath
        }
    }

    return [pscustomobject]$exported
}

function ConvertTo-OfficeColor {
    param([string]$Hex)

    $clean = $Hex.TrimStart('#')
    $r = [Convert]::ToInt32($clean.Substring(0, 2), 16)
    $g = [Convert]::ToInt32($clean.Substring(2, 2), 16)
    $b = [Convert]::ToInt32($clean.Substring(4, 2), 16)
    return ($r + ($g * 256) + ($b * 65536))
}

function Add-PptText {
    param(
        [object]$Slide,
        [string]$Text,
        [double]$Left,
        [double]$Top,
        [double]$Width,
        [double]$Height,
        [int]$FontSize = 18,
        [string]$Color = '#1F2937',
        [switch]$Bold
    )

    $shape = $Slide.Shapes.AddTextbox(1, $Left, $Top, $Width, $Height)
    $shape.TextFrame.TextRange.Text = $Text
    $shape.TextFrame.TextRange.Font.Name = 'Aptos'
    $shape.TextFrame.TextRange.Font.Size = $FontSize
    $shape.TextFrame.TextRange.Font.Color.RGB = ConvertTo-OfficeColor -Hex $Color
    if ($Bold) {
        $shape.TextFrame.TextRange.Font.Bold = -1
    }
    return $shape
}

function Add-PptRect {
    param(
        [object]$Slide,
        [double]$Left,
        [double]$Top,
        [double]$Width,
        [double]$Height,
        [string]$Fill = '#FFFFFF',
        [string]$Line = '#D1D5DB'
    )

    $shape = $Slide.Shapes.AddShape(1, $Left, $Top, $Width, $Height)
    $shape.Fill.ForeColor.RGB = ConvertTo-OfficeColor -Hex $Fill
    $shape.Line.ForeColor.RGB = ConvertTo-OfficeColor -Hex $Line
    return $shape
}

function Add-PptTitleSlide {
    param(
        [object]$Presentation,
        [object]$Report
    )

    $slide = $Presentation.Slides.Add($Presentation.Slides.Count + 1, 12)
    $slide.FollowMasterBackground = $false
    $slide.Background.Fill.ForeColor.RGB = ConvertTo-OfficeColor -Hex '#0F172A'
    Add-PptText -Slide $slide -Text 'Active Directory Enumeration Report' -Left 54 -Top 95 -Width 620 -Height 70 -FontSize 34 -Color '#FFFFFF' -Bold | Out-Null
    Add-PptText -Slide $slide -Text $Report.Context.DnsRoot -Left 56 -Top 165 -Width 620 -Height 36 -FontSize 20 -Color '#93C5FD' | Out-Null
    Add-PptText -Slide $slide -Text ("Generated: {0}" -f $Report.GeneratedAt) -Left 56 -Top 220 -Width 620 -Height 28 -FontSize 14 -Color '#CBD5E1' | Out-Null
    Add-PptRect -Slide $slide -Left 56 -Top 300 -Width 150 -Height 54 -Fill '#DC2626' -Line '#DC2626' | Out-Null
    Add-PptText -Slide $slide -Text ("Critical: {0}" -f $Report.Summary.Critical) -Left 66 -Top 314 -Width 130 -Height 24 -FontSize 16 -Color '#FFFFFF' -Bold | Out-Null
    Add-PptRect -Slide $slide -Left 222 -Top 300 -Width 150 -Height 54 -Fill '#F59E0B' -Line '#F59E0B' | Out-Null
    Add-PptText -Slide $slide -Text ("Medium: {0}" -f $Report.Summary.Medium) -Left 232 -Top 314 -Width 130 -Height 24 -FontSize 16 -Color '#111827' -Bold | Out-Null
    Add-PptRect -Slide $slide -Left 388 -Top 300 -Width 150 -Height 54 -Fill '#16A34A' -Line '#16A34A' | Out-Null
    Add-PptText -Slide $slide -Text ("Low/Info: {0}" -f ($Report.Summary.Low + $Report.Summary.Info)) -Left 398 -Top 314 -Width 130 -Height 24 -FontSize 16 -Color '#FFFFFF' -Bold | Out-Null
}

function Add-PptSlide {
    param(
        [object]$Presentation,
        [string]$Title
    )

    $slide = $Presentation.Slides.Add($Presentation.Slides.Count + 1, 12)
    $slide.FollowMasterBackground = $false
    $slide.Background.Fill.ForeColor.RGB = ConvertTo-OfficeColor -Hex '#F8FAFC'
    Add-PptText -Slide $slide -Text $Title -Left 36 -Top 24 -Width 650 -Height 36 -FontSize 24 -Color '#111827' -Bold | Out-Null
    Add-PptRect -Slide $slide -Left 36 -Top 68 -Width 648 -Height 2 -Fill '#2563EB' -Line '#2563EB' | Out-Null
    return $slide
}

function Add-PptBullets {
    param(
        [object]$Slide,
        [string[]]$Items,
        [double]$Left = 56,
        [double]$Top = 100,
        [double]$Width = 600,
        [double]$Height = 300,
        [int]$FontSize = 15
    )

    $text = (($Items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
    $shape = Add-PptText -Slide $Slide -Text $text -Left $Left -Top $Top -Width $Width -Height $Height -FontSize $FontSize -Color '#1F2937'
    return $shape
}

function Add-PptTable {
    param(
        [object]$Slide,
        [object[]]$Rows,
        [string[]]$Columns,
        [double]$Left,
        [double]$Top,
        [double]$Width,
        [double]$Height,
        [int]$MaxRows = 8
    )

    $data = @($Rows | Select-Object -First $MaxRows)
    if ($data.Count -eq 0) {
        Add-PptText -Slide $Slide -Text 'No records.' -Left $Left -Top $Top -Width $Width -Height 28 -FontSize 14 -Color '#16A34A' | Out-Null
        return
    }

    $rowsCount = $data.Count + 1
    $colsCount = $Columns.Count
    $shape = $Slide.Shapes.AddTable($rowsCount, $colsCount, $Left, $Top, $Width, $Height)
    $table = $shape.Table

    for ($c = 1; $c -le $colsCount; $c++) {
        $cell = $table.Cell(1, $c).Shape
        $cell.Fill.ForeColor.RGB = ConvertTo-OfficeColor -Hex '#1E40AF'
        $cell.TextFrame.TextRange.Text = $Columns[$c - 1]
        $cell.TextFrame.TextRange.Font.Name = 'Aptos'
        $cell.TextFrame.TextRange.Font.Size = 10
        $cell.TextFrame.TextRange.Font.Color.RGB = ConvertTo-OfficeColor -Hex '#FFFFFF'
        $cell.TextFrame.TextRange.Font.Bold = -1
    }

    for ($r = 0; $r -lt $data.Count; $r++) {
        $row = $data[$r]
        $riskColor = '#FFFFFF'
        if ($row.PSObject.Properties.Name -contains 'Risk') {
            switch ($row.Risk) {
                'Critical' { $riskColor = '#FEE2E2' }
                'Medium' { $riskColor = '#FEF3C7' }
                'Low' { $riskColor = '#DCFCE7' }
                'Info' { $riskColor = '#DBEAFE' }
            }
        }

        for ($c = 1; $c -le $colsCount; $c++) {
            $column = $Columns[$c - 1]
            $cell = $table.Cell($r + 2, $c).Shape
            $cell.Fill.ForeColor.RGB = ConvertTo-OfficeColor -Hex $riskColor
            $cell.TextFrame.TextRange.Text = ConvertTo-DisplayString -Value $row.$column -MaxLength 58
            $cell.TextFrame.TextRange.Font.Name = 'Aptos'
            $cell.TextFrame.TextRange.Font.Size = 8
            $cell.TextFrame.TextRange.Font.Color.RGB = ConvertTo-OfficeColor -Hex '#111827'
        }
    }
}

function Add-PptRiskBars {
    param(
        [object]$Slide,
        [object]$Summary,
        [double]$Left,
        [double]$Top
    )

    $items = @(
        @{ Name = 'Critical'; Count = [int]$Summary.Critical; Color = '#DC2626' },
        @{ Name = 'Medium'; Count = [int]$Summary.Medium; Color = '#F59E0B' },
        @{ Name = 'Low'; Count = [int]$Summary.Low; Color = '#16A34A' },
        @{ Name = 'Info'; Count = [int]$Summary.Info; Color = '#2563EB' }
    )

    $max = [Math]::Max(1, ($items | Measure-Object -Property Count -Maximum).Maximum)
    $y = $Top
    foreach ($item in $items) {
        Add-PptText -Slide $Slide -Text $item.Name -Left $Left -Top $y -Width 90 -Height 20 -FontSize 12 -Color '#111827' -Bold | Out-Null
        Add-PptRect -Slide $Slide -Left ($Left + 100) -Top ($y + 2) -Width 320 -Height 16 -Fill '#E5E7EB' -Line '#E5E7EB' | Out-Null
        $barWidth = [Math]::Max(8, (320 * ([double]$item.Count / [double]$max)))
        Add-PptRect -Slide $Slide -Left ($Left + 100) -Top ($y + 2) -Width $barWidth -Height 16 -Fill $item.Color -Line $item.Color | Out-Null
        Add-PptText -Slide $Slide -Text ([string]$item.Count) -Left ($Left + 430) -Top ($y - 1) -Width 50 -Height 20 -FontSize 12 -Color '#111827' -Bold | Out-Null
        $y += 34
    }
}

function New-PowerPointReport {
    param(
        [Parameter(Mandatory = $true)][object]$Report,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($NoPowerPoint) {
        return $null
    }

    Write-Status -Message 'Generating PowerPoint executive report.'

    $powerPoint = $null
    $presentation = $null

    try {
        $powerPoint = New-Object -ComObject PowerPoint.Application
        $powerPoint.Visible = $true
        $presentation = $powerPoint.Presentations.Add()

        Add-PptTitleSlide -Presentation $presentation -Report $Report

        $slide = Add-PptSlide -Presentation $presentation -Title 'Overview of Domain'
        Add-PptBullets -Slide $slide -Items @(
            ("Domain: {0}" -f $Report.Context.DnsRoot),
            ("Distinguished Name: {0}" -f $Report.Context.DistinguishedName),
            ("Domain Controller / Server: {0}" -f $Report.Context.Server),
            ("Users: {0}; Groups: {1}; Computers: {2}; GPOs: {3}; Trusts: {4}" -f $Report.Users.Count, $Report.Groups.Count, $Report.Computers.Count, $Report.GPOs.Count, $Report.Trusts.Count),
            ("Attack paths inferred: {0}; Relationship edges: {1}" -f $Report.AttackPaths.Count, $Report.RelationshipEdges.Count)
        ) | Out-Null

        $slide = Add-PptSlide -Presentation $presentation -Title 'Users Analysis'
        Add-PptTable -Slide $slide -Rows @(
            [pscustomobject]@{ Metric = 'Total users'; Value = $Report.Users.Count; Risk = 'Info' },
            [pscustomobject]@{ Metric = 'Kerberoastable users'; Value = @($Report.Users | Where-Object { $_.IsKerberoastable }).Count; Risk = 'Critical' },
            [pscustomobject]@{ Metric = 'AS-REP roastable users'; Value = @($Report.Users | Where-Object { $_.IsAsRepRoastable }).Count; Risk = 'Critical' },
            [pscustomobject]@{ Metric = 'AdminCount=1 users'; Value = @($Report.Users | Where-Object { $_.AdminCount }).Count; Risk = 'Critical' },
            [pscustomobject]@{ Metric = 'Password never expires'; Value = @($Report.Users | Where-Object { $_.PasswordNeverExpires }).Count; Risk = 'Medium' },
            [pscustomobject]@{ Metric = 'Disabled users'; Value = @($Report.Users | Where-Object { $_.IsDisabled }).Count; Risk = 'Low' }
        ) -Columns @('Metric', 'Value', 'Risk') -Left 56 -Top 100 -Width 600 -Height 230 -MaxRows 8

        $slide = Add-PptSlide -Presentation $presentation -Title 'Privileged Accounts'
        Add-PptTable -Slide $slide -Rows @($Report.Users | Where-Object { $_.IsPrivileged } | Sort-Object SamAccountName) -Columns @('SamAccountName', 'AdminCount', 'PrivilegeReason', 'IsKerberoastable') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 9

        $slide = Add-PptSlide -Presentation $presentation -Title 'Kerberoasting Findings'
        Add-PptTable -Slide $slide -Rows @($Report.Users | Where-Object { $_.IsKerberoastable } | Sort-Object IsPrivileged, SamAccountName -Descending) -Columns @('SamAccountName', 'IsPrivileged', 'PasswordNeverExpires', 'ServicePrincipalNames') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 9

        $slide = Add-PptSlide -Presentation $presentation -Title 'AS-REP Findings'
        Add-PptTable -Slide $slide -Rows @($Report.Users | Where-Object { $_.IsAsRepRoastable } | Sort-Object IsPrivileged, SamAccountName -Descending) -Columns @('SamAccountName', 'IsPrivileged', 'PasswordNeverExpires', 'LastLogonTimestamp') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 9

        $slide = Add-PptSlide -Presentation $presentation -Title 'Groups and Privileges'
        Add-PptTable -Slide $slide -Rows @($Report.Groups | Where-Object { $_.IsDangerousGroup -or (-not $_.IsDefaultGroup) } | Sort-Object IsCriticalGroup, NestedMemberCount -Descending) -Columns @('SamAccountName', 'IsDefaultGroup', 'IsCriticalGroup', 'MemberCount', 'NestedMemberCount') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 10

        $slide = Add-PptSlide -Presentation $presentation -Title 'Machines and OS Risks'
        Add-PptTable -Slide $slide -Rows @($Report.Computers | Where-Object { $_.IsDomainController -or $_.IsOutdatedOS -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation } | Sort-Object IsDomainController, IsOutdatedOS -Descending) -Columns @('SamAccountName', 'OperatingSystem', 'IsDomainController', 'IsOutdatedOS', 'UnconstrainedDelegation') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 10

        $slide = Add-PptSlide -Presentation $presentation -Title 'Attack Paths'
        Add-PptTable -Slide $slide -Rows @($Report.AttackPaths | Sort-Object RiskRank -Descending) -Columns @('Risk', 'Name', 'Start', 'End', 'Evidence') -Left 36 -Top 94 -Width 648 -Height 330 -MaxRows 9

        $slide = Add-PptSlide -Presentation $presentation -Title 'Risk Summary'
        Add-PptRiskBars -Slide $slide -Summary $Report.Summary -Left 70 -Top 110
        Add-PptRect -Slide $slide -Left 70 -Top 235 -Width 520 -Height 26 -Fill '#EFF6FF' -Line '#BFDBFE' | Out-Null
        Add-PptText -Slide $slide -Text '[KR] Kerberoast   [AR] AS-REP   [DL] Delegation   [ACL] Permissions   [GPO] Policy Abuse' -Left 82 -Top 240 -Width 500 -Height 16 -FontSize 10 -Color '#1E3A8A' -Bold | Out-Null
        Add-PptTable -Slide $slide -Rows @($Report.Findings | Sort-Object RiskRank -Descending | Select-Object -First 7) -Columns @('Risk', 'Category', 'Name', 'AttackVector') -Left 70 -Top 270 -Width 570 -Height 150 -MaxRows 7

        $slide = Add-PptSlide -Presentation $presentation -Title 'Recommendations'
        Add-PptBullets -Slide $slide -Items @(
            'Remove Kerberoastable SPNs from privileged user accounts; migrate services to gMSA or least-privilege service accounts.',
            'Enable Kerberos pre-authentication on all users and rotate passwords for exposed AS-REP accounts.',
            'Eliminate unconstrained delegation and tightly scope constrained/resource-based delegation.',
            'Review AdminCount=1 accounts, AdminSDHolder, nested privileged groups, and stale administrator membership.',
            'Remove dangerous ACLs such as GenericAll, GenericWrite, WriteDACL, and WriteOwner from non-administrative principals.',
            'Harden GPO delegation, remove legacy cpassword XML, and audit startup/shutdown/logon/logoff scripts.',
            'Retire or isolate outdated systems and prioritize those with SPNs, delegation, or administrative services.',
            'Validate all trusts for direction, filtering, selective authentication, and cross-domain privileged access.'
        ) -Left 46 -Top 92 -Width 640 -Height 330 -FontSize 12 | Out-Null

        $slide = Add-PptSlide -Presentation $presentation -Title 'Conclusion'
        Add-PptBullets -Slide $slide -Items @(
            ("Assessment produced {0} findings and {1} inferred attack paths." -f $Report.Findings.Count, $Report.AttackPaths.Count),
            ("Highest risk concentration: Critical={0}, Medium={1}." -f $Report.Summary.Critical, $Report.Summary.Medium),
            'Prioritize privileged roastable accounts, delegation, dangerous ACLs, GPO control paths, and legacy systems.',
            'Use exported JSON/CSV evidence for remediation tracking and deeper BloodHound-style graph validation.'
        ) -Left 56 -Top 110 -Width 610 -Height 280 -FontSize 16 | Out-Null

        $presentation.SaveAs($Path)
        $presentation.Close()
        $powerPoint.Quit()
        return $Path
    }
    catch {
        Write-Status -Message ("PowerPoint generation failed: {0}" -f $_.Exception.Message) -Color Yellow
        return $null
    }
    finally {
        if ($null -ne $presentation) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($presentation) } catch {}
        }
        if ($null -ne $powerPoint) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($powerPoint) } catch {}
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Show-ConsoleReport {
    param([object]$Report)

    Write-Section -Name 'DOMAIN OVERVIEW' -Color Blue
    Write-StructuredTable -Rows @([pscustomobject]@{
            Domain = $Report.Context.DnsRoot
            Server = $Report.Context.Server
            Users = $Report.Users.Count
            Groups = $Report.Groups.Count
            Machines = $Report.Computers.Count
            GPOs = $Report.GPOs.Count
            Trusts = $Report.Trusts.Count
        }) -Columns @('Domain', 'Server', 'Users', 'Groups', 'Machines', 'GPOs', 'Trusts') -MaxRows 5

    Write-Section -Name 'RISK SUMMARY' -Color Blue
    Write-StructuredTable -Rows @(
        [pscustomobject]@{ Risk = 'Critical'; Count = $Report.Summary.Critical; Meaning = 'Exploitable or direct privilege path' },
        [pscustomobject]@{ Risk = 'Medium'; Count = $Report.Summary.Medium; Meaning = 'Weak configuration or attack surface' },
        [pscustomobject]@{ Risk = 'Low'; Count = $Report.Summary.Low; Meaning = 'Hygiene or informational risk' },
        [pscustomobject]@{ Risk = 'Info'; Count = $Report.Summary.Info; Meaning = 'General data' }
    ) -Columns @('Risk', 'Count', 'Meaning') -MaxRows 10

    Write-Section -Name 'USERS' -Color Blue
    Write-StructuredTable -Rows @($Report.Users | Where-Object { $_.IsKerberoastable -or $_.IsAsRepRoastable -or $_.IsPrivileged -or $_.PasswordNeverExpires -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation } | Select-Object @{n='Risk';e={ if ($_.IsKerberoastable -or $_.IsAsRepRoastable -or $_.IsPrivileged -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation) { 'Critical' } else { 'Medium' } }}, SamAccountName, IsPrivileged, IsKerberoastable, IsAsRepRoastable, PasswordNeverExpires, PrivilegeReason) -Columns @('Risk', 'SamAccountName', 'IsPrivileged', 'IsKerberoastable', 'IsAsRepRoastable', 'PasswordNeverExpires', 'PrivilegeReason') -MaxRows $MaxConsoleRows

    Write-Section -Name 'GROUPS' -Color Blue
    Write-StructuredTable -Rows @($Report.Groups | Where-Object { $_.IsDangerousGroup -or (-not $_.IsDefaultGroup) } | Sort-Object IsCriticalGroup, NestedMemberCount -Descending | Select-Object @{n='Risk';e={ if ($_.IsCriticalGroup -and $_.NestedMemberCount -gt 0) { 'Critical' } elseif ($_.IsDangerousGroup) { 'Medium' } else { 'Info' } }}, SamAccountName, IsDefaultGroup, IsCriticalGroup, MemberCount, NestedMemberCount) -Columns @('Risk', 'SamAccountName', 'IsDefaultGroup', 'IsCriticalGroup', 'MemberCount', 'NestedMemberCount') -MaxRows $MaxConsoleRows

    Write-Section -Name 'MACHINES' -Color Blue
    Write-StructuredTable -Rows @($Report.Computers | Where-Object { $_.IsDomainController -or $_.IsOutdatedOS -or $_.UnconstrainedDelegation -or $_.ConstrainedDelegation -or $_.LateralMovementServices.Count -gt 0 } | Select-Object @{n='Risk';e={ if ($_.UnconstrainedDelegation -or $_.ConstrainedDelegation) { 'Critical' } elseif ($_.IsOutdatedOS -or $_.LateralMovementServices.Count -gt 0) { 'Medium' } else { 'Info' } }}, SamAccountName, DnsHostName, OperatingSystem, IsDomainController, IsOutdatedOS, UnconstrainedDelegation) -Columns @('Risk', 'SamAccountName', 'DnsHostName', 'OperatingSystem', 'IsDomainController', 'IsOutdatedOS', 'UnconstrainedDelegation') -MaxRows $MaxConsoleRows

    Write-Section -Name 'GPO' -Color Blue
    Write-StructuredTable -Rows @($Report.GPOs | Where-Object { $_.ScriptCount -gt 0 -or $_.CPasswordFileCount -gt 0 -or $_.LinkCount -gt 0 } | Select-Object @{n='Risk';e={ if ($_.CPasswordFileCount -gt 0) { 'Critical' } elseif ($_.ScriptCount -gt 0) { 'Medium' } else { 'Info' } }}, DisplayName, LinkCount, ScriptCount, CPasswordFileCount, LinkedTargets) -Columns @('Risk', 'DisplayName', 'LinkCount', 'ScriptCount', 'CPasswordFileCount', 'LinkedTargets') -MaxRows $MaxConsoleRows

    Write-Section -Name 'ACL / PERMISSIONS' -Color Blue
    Write-StructuredTable -Rows @($Report.AclFindings | Sort-Object RiskRank -Descending | Select-Object Risk, Principal, Rights, ObjectType, ObjectName, IsInherited) -Columns @('Risk', 'Principal', 'Rights', 'ObjectType', 'ObjectName', 'IsInherited') -MaxRows $MaxConsoleRows

    Write-Section -Name 'TRUSTS' -Color Blue
    Write-StructuredTable -Rows @($Report.Trusts | Select-Object @{n='Risk';e={ if ($_.Direction -eq 'Bidirectional') { 'Medium' } else { 'Info' } }}, TrustPartner, Direction, Type, AttributeFlags) -Columns @('Risk', 'TrustPartner', 'Direction', 'Type', 'AttributeFlags') -MaxRows $MaxConsoleRows

    Write-Section -Name 'ATTACK PATHS' -Color Blue
    Write-StructuredTable -Rows @($Report.AttackPaths | Sort-Object RiskRank -Descending) -Columns @('Risk', 'Id', 'Name', 'Start', 'End', 'Evidence') -MaxRows $MaxConsoleRows

    Write-Section -Name 'TOP FINDINGS' -Color Blue
    Write-StructuredTable -Rows @($Report.Findings | Sort-Object RiskRank -Descending | Select-Object -First $MaxConsoleRows) -Columns @('Risk', 'Id', 'Category', 'Name', 'AttackVector', 'Evidence') -MaxRows $MaxConsoleRows
}

function Invoke-ADEnumeration {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $script:ADContext = Initialize-ADContext -Server $PDC -SearchBase $DN

    $lookupProperty = $Property
    if ([string]::IsNullOrWhiteSpace($lookupProperty)) {
        $lookupProperty = $Propertie
    }

    if (Invoke-LegacyLookup -Type $ObjType -LookupName $Name -LookupProperty $lookupProperty) {
        return $null
    }

    Write-Section -Name 'ACTIVE DIRECTORY ENUMERATION' -Color Blue
    Write-Status -Message ("Domain: {0}" -f $script:ADContext.DnsRoot)
    Write-Status -Message ("Search base: {0}" -f $script:ADContext.DistinguishedName)
    Write-Status -Message ("Server: {0}" -f $script:ADContext.Server)

    $users = @()
    $groups = @()
    $computers = @()

    if ($ObjType -in @('All', 'U', 'Users')) {
        $users = Get-ADUsersAdvanced
    }
    if ($ObjType -in @('All', 'G', 'Groups')) {
        $groups = Get-ADGroupsAdvanced
    }
    if ($ObjType -in @('All', 'M', 'Machines')) {
        $computers = Get-ADComputersAdvanced
    }

    if ($ObjType -ne 'All') {
        if ($groups.Count -eq 0) {
            $groups = Get-ADGroupsAdvanced
        }
    }

    $gpos = Get-ADGposAdvanced
    $trusts = Get-ADTrustsAdvanced

    Invoke-RiskAnalysis -Users $users -Groups $groups -Computers $computers -Gpos $gpos -Trusts $trusts
    $aclFindings = Invoke-AclAnalysis -Users $users -Groups $groups -Computers $computers -Gpos $gpos
    Invoke-AttackPathAnalysis -Users $users -Groups $groups -Computers $computers -Gpos $gpos -AclFindings $aclFindings

    $summary = Get-RiskSummary -Findings @($script:Findings)
    $report = [pscustomobject]@{
        GeneratedAt = Get-Date
        Context = [pscustomobject]@{
            DnsRoot = $script:ADContext.DnsRoot
            DistinguishedName = $script:ADContext.DistinguishedName
            Server = $script:ADContext.Server
            ConfigurationNamingContext = $script:ADContext.ConfigurationNamingContext
            SchemaNamingContext = $script:ADContext.SchemaNamingContext
            DomainFunctionality = $script:ADContext.DomainFunctionality
            ForestFunctionality = $script:ADContext.ForestFunctionality
        }
        Summary = $summary
        Users = @($users)
        Groups = @($groups)
        Computers = @($computers)
        GPOs = @($gpos)
        Trusts = @($trusts)
        Findings = @($script:Findings)
        AclFindings = @($aclFindings)
        AttackPaths = @($script:AttackPaths)
        RelationshipEdges = @($script:RelationshipEdges)
    }

    Show-ConsoleReport -Report $report

    $exports = Export-ADEnumData -Report $report -Directory $OutputDirectory
    $pptPath = Join-Path $OutputDirectory 'ADEnum_Report.pptx'
    $pptResult = New-PowerPointReport -Report $report -Path $pptPath

    Write-Section -Name 'EXPORTS' -Color Blue
    if ($null -ne $exports.Json) {
        Write-Host ("JSON: {0}" -f $exports.Json) -ForegroundColor Green
    }
    if (-not $NoCsv) {
        Write-Host ("CSV directory: {0}" -f $OutputDirectory) -ForegroundColor Green
    }
    if ($null -ne $pptResult) {
        Write-Host ("PowerPoint: {0}" -f $pptResult) -ForegroundColor Green
    }
    elseif (-not $NoPowerPoint) {
        Write-Host 'PowerPoint was not generated. Ensure Microsoft PowerPoint is installed and COM automation is permitted.' -ForegroundColor Yellow
    }

    return $report
}

Invoke-ADEnumeration | Out-Null