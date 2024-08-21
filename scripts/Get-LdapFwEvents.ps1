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

    $DN = [regex]::Match($Event.Message, 'DN:\s*(.*?)(?=\r|\n)')

    $Attributes = [regex]::Match($Event.Message, 'Attributes:(.\t*)(.*[^\r|\n|\t])').Groups[2].Value

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

    return New-Object PSObject -Property @{
        'Log Source' = 'LDAPFW'
        'Event Type' = $EventType
        'TimeCreated' = $Event.TimeCreated
        'Security ID' = [regex]::Match($Event.Message, 'Security ID:\s*(.*?)($|\r\n)').Groups[1].Value
        'Action' = [regex]::Match($Event.Message, 'Action:\s*(.*?)($|\r\n)').Groups[1].Value
        'DN' = $DN.Groups[1].Value
        'Filter' = [regex]::Match($Event.Message, 'Filter:\s*(.*?)(?=\r|\n)').Groups[1].Value
        'Scope' = [regex]::Match($Event.Message, 'Scope:\s*(.*?)($|\r\n)').Groups[1].Value
        'Attributes' = $Attributes
        'Entry List' = $EntryList
        'Value' = $Value
        'New DN' = $DN.Groups[2].Value
        'Delete Old' = [regex]::Match($Event.Message, 'Delete Old:\s*(.*?)($|\r\n)').Groups[1].Value
        'Oid' = [regex]::Match($Event.Message, 'Oid:\s*(.*?)($|\r\n)').Groups[1].Value
        'Data' = $Data
        'Client Network Address' = [regex]::Match($Event.Message, 'Client Network Address:\s*([\d\.:a-zU]+)').Groups[1].Value
        'Client Port' = [regex]::Match($Event.Message, 'Client Port:\s*(.*?)($|\r\n)').Groups[1].Value
    }
}

# Retrieve and parse LDAPFW events
$LDAPFWEvents = Get-WinEvent -LogName LDAPFW -ErrorAction SilentlyContinue | ForEach-Object { Parse-LDAPFWLog $_ }

# Sort combined events by time
$SortedEvents = $LDAPFWEvents | Sort-Object -Property TimeCreated

# Export combined events to CSV
$SortedEvents | Export-Csv -Path "LDAPFW_Log_Events.csv" -NoTypeInformation
