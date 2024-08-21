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
    $ClientNetworkAddress = [regex]::Match($Event.Message, 'Client Network Address:\s*([\d\.]+)').Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($ClientNetworkAddress)) {
        $ClientNetworkAddress = "Unknown"
    }
    $BaseDNMatch = [regex]::Match($Event.Message, '(?<=Base DN:\s*)(.*?)(?=\r|\n)')
    $BaseDN = if ($BaseDNMatch.Success) { $BaseDNMatch.Value.Trim() } else { "Null" }
    $FilterMatch = [regex]::Match($Event.Message, '(?<=Filter:\s*)(.*?)(?=\r|\n)')
    $Filter = if ($FilterMatch.Success) { $FilterMatch.Value.Trim() } else { "Null" }
    $AttributesMatch = [regex]::Match($Event.Message, 'Attributes:\s*(.*?)($|\r\n)')
    $Attributes = if ($AttributesMatch.Success) { $AttributesMatch.Groups[1].Value } else { "Null" }
    return New-Object PSObject -Property @{
        'Log Source' = 'LDAPFW'
        'Event Type' = $EventType
        'TimeCreated' = $Event.TimeCreated
        'Security ID' = [regex]::Match($Event.Message, 'Security ID:\s*(.*?)($|\r\n)').Groups[1].Value
        'Base DN' = $BaseDN
        'Filter' = $Filter
        'Scope' = [regex]::Match($Event.Message, 'Scope:\s*(.*?)($|\r\n)').Groups[1].Value
        'Attributes' = $Attributes
        'Client Network Address' = $ClientNetworkAddress
        'Client Port' = [regex]::Match($Event.Message, 'Client Port:\s*(.*?)($|\r\n)').Groups[1].Value
    }
}

# Retrieve and parse LDAPFW events
$LDAPFWEvents = Get-WinEvent -LogName LDAPFW -ErrorAction SilentlyContinue | ForEach-Object { Parse-LDAPFWLog $_ }

# Sort combined events by time
$SortedEvents = $LDAPFWEvents | Sort-Object -Property TimeCreated

# Export combined events to CSV
$SortedEvents | Export-Csv -Path "LDAPFW_Log_Events.csv" -NoTypeInformation
