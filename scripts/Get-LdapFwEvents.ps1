# Function to parse LDAPFW logs
function Parse-LDAPFWLog {
    param ($Event)
    $EventID = $Event.Id
    $EventType = switch ($EventID) {
        257 {'Install'}
        258 {'Uninstall'}
        259 {'Add'}
        260 {'Delete'}
        261 {'Modify'}
        262 {'ModifyDN'}
        263 {'Search'}
        264 {'Compare'}
        265 {'Extended'}
        266 {'ConfigUpdate'}
        default { $EventID }
    }

    $DN = ""
    $NewDN = ""

    $DNMatches = [regex]::Matches($Event.Message, 'DN:(.\t*)(.*[^\r|\n|\t])')

    if ($DNMatches.Count -gt 0) {
        $DN = $DNMatches[0].Groups[2].Value
    }

    if ($DNMatches.Count -gt 1) {
        $NewDN = $DNMatches[1].Groups[2].Value
    }

    $Attributes = [regex]::Match($Event.Message, 'Attribute[s]?:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

    if ([string]::IsNullOrWhiteSpace($Attributes)) {
        $Attributes = ""
    }

    $EntryList = [regex]::Match($Event.Message, 'Entry List:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

    if ([string]::IsNullOrWhiteSpace($EntryList)) {
        $EntryList = ""
    }

    $Value = [regex]::Match($Event.Message, 'Value:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = ""
    }

    $Data = [regex]::Match($Event.Message, 'Data:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

    if ([string]::IsNullOrWhiteSpace($Data)) {
        $Data = ""
    }
	
    $Oid = [regex]::Match($Event.Message, 'Oid:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

    if ([string]::IsNullOrWhiteSpace($Oid)) {
        $Oid = ""
    }

    return New-Object PSObject -Property $([ordered]@{
        LogSource = 'LDAPFW'
        TimeCreated = $Event.TimeCreated
        EventType = $EventType
        SecurityID = [regex]::Match($Event.Message, 'Security ID:\s*(.*?)($|\r\n)').Groups[1].Value
        ClientNetworkAddress = [regex]::Match($Event.Message, 'Client Network Address:\s*([\d\.:a-zU]+)').Groups[1].Value
        ClientPort = [regex]::Match($Event.Message, 'Client Port:\s*(.*?)($|\r\n)').Groups[1].Value
        Action = [regex]::Match($Event.Message, 'Action:\s*(.*?)($|\r\n)').Groups[1].Value
        DN = $DN
        SearchFilter = [regex]::Match($Event.Message, 'Filter:\s*(.*?)(?=\r|\n)').Groups[1].Value
        Scope = [regex]::Match($Event.Message, 'Scope:\s*(.*?)($|\r\n)').Groups[1].Value
        Attributes = $Attributes
        EntryList = $EntryList
        Value = $Value
        NewDN = $NewDN
        DeleteOld = [regex]::Match($Event.Message, 'Delete Old:\s*(.*?)($|\r\n)').Groups[1].Value
        ExtendedOid = $Oid
        ExtendedData = $Data
    })
}

# Retrieve and parse LDAPFW events
$LDAPFWEvents = Get-WinEvent -LogName LDAPFW -ErrorAction SilentlyContinue | ForEach-Object { Parse-LDAPFWLog $_ }

# Sort combined events by time
$SortedEvents = $LDAPFWEvents | Sort-Object -Property TimeCreated

# Export combined events to CSV
$SortedEvents | Export-Csv -Path "LDAPFW_Log_Events.csv" -NoTypeInformation
