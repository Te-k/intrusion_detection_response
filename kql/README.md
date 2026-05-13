# KQL for Defender & Sentinel

This folder gather useful KQL queries and information along with knowledge on MS Defender and Sentinel.

KQL resources:
* https://www.kqlsearch.com/


## Load external resources

The [externaldata](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator?view=microsoft-fabric) operator can be used to load external sources, mostly as JSON, CSV or TXT files.

That's for instance how microsoft is often suggesting to search for IOCs based on IOC CSV files, like [here](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/EUROPIUM%20_September2022.yaml)

```kql
let iocs = externaldata(DateAdded:string,IoC:string,Type:string,TLP:string) [@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Europium_September2022.csv"] with (format="csv", ignoreFirstRecord=True);
let sha256Hashes = (iocs | where Type =~ "sha256" | project IoC);
let IPList = (iocs | where Type =~ "ip"| project IoC);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
(union isfuzzy=true
(CommonSecurityLog
| where SourceIP in (IPList) or DestinationIP in (IPList) or Message has_any (IPList)
| parse Message with * '(' DNSName ')' * 
| project TimeGenerated, SourceIP, DestinationIP, Message, SourceUserID, RequestURL, DNSName, Type
| extend MessageIP = extract(IPRegex, 0, Message), RequestIP = extract(IPRegex, 0, RequestURL)
| extend IPMatch = case(SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", MessageIP in (IPList), "Message",  "NoMatch")
| extend timestamp = TimeGenerated, IPEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, IPMatch == "Message", MessageIP, "NoMatch")
),
(DnsEvents
| where IPAddresses in (IPList)  
| project TimeGenerated, Computer, IPAddresses, Name, ClientIP, Type
| extend DestinationIPAddress = IPAddresses, DNSName = Name, Computer 
| extend timestamp = TimeGenerated, IPEntity = DestinationIPAddress, HostEntity = Computer
),
(VMConnection
| where SourceIp in (IPList) or DestinationIp in (IPList)
| parse RemoteDnsCanonicalNames with * '["' DNSName '"]' *
| project TimeGenerated, Computer, Direction, ProcessName, SourceIp, DestinationIp, DestinationPort, RemoteDnsQuestions, DNSName,BytesSent, BytesReceived, RemoteCountry, Type
| extend IPMatch = case( SourceIp in (IPList), "SourceIP", DestinationIp in (IPList), "DestinationIP", "None") 
| extend timestamp = TimeGenerated, IPEntity = case(IPMatch == "SourceIP", SourceIp, IPMatch == "DestinationIP", DestinationIp, "NoMatch"), File = ProcessName, HostEntity = Computer
),
(Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 3
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend SourceIP = tostring(EventDetail.[9].["#text"]), DestinationIP = tostring(EventDetail.[14].["#text"]), Image = tostring(EventDetail.[4].["#text"])
| where SourceIP in (IPList) or DestinationIP in (IPList)
| project TimeGenerated, SourceIP, DestinationIP, Image, UserName, Computer, Type
| extend IPMatch = case( SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated, File = tostring(split(Image, '\\', -1)[-1]), IPEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None"), 
HostEntity = Computer, AccountName = tostring(split(UserName, @'\')[1]), AccountDomain = tostring(split(UserName, @'\')[0])
| extend InitiatingProcessAccount = UserName
), 
(OfficeActivity
| where ClientIP in (IPList) 
| project TimeGenerated, UserAgent, Operation, RecordType, UserId, ClientIP, Type
| extend timestamp = TimeGenerated, IPEntity = ClientIP, AccountName = tostring(split(UserId, "@")[0]), AccountDomain = tostring(split(UserId, "@")[1])
| extend InitiatingProcessAccount = UserId
),
(DeviceNetworkEvents
| where RemoteIP in (IPList) or InitiatingProcessSHA256 in (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, Computer = DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, 
InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, LocalIP, Type
| extend timestamp = TimeGenerated, IPEntity = RemoteIP, HostEntity = Computer, AccountName = InitiatingProcessAccountName, AccountDomain = InitiatingProcessAccountDomain
| extend InitiatingProcessAccount = strcat(AccountDomain, "\\", AccountName)
),
(WindowsFirewall
| where SourceIP in (IPList) or DestinationIP in (IPList) 
| project TimeGenerated, Computer, CommunicationDirection, SourceIP, DestinationIP, SourcePort, DestinationPort, Type
| extend IPMatch = case( SourceIP in (IPList), "SourceIP", DestinationIP in (IPList), "DestinationIP", "None")
| extend timestamp = TimeGenerated, HostEntity = Computer, IPEntity = case(IPMatch == "SourceIP", SourceIP, IPMatch == "DestinationIP", DestinationIP, "None")
), 
(imFileEvent
| where TargetFileSHA256 has_any (sha256Hashes)
| extend Account = ActorUsername, Computer = DvcHostname, IPAddress = SrcIpAddr, CommandLine = ActingProcessCommandLine, FileHash = TargetFileSHA256
| project Type, TimeGenerated, Computer, Account, IPAddress, CommandLine, FileHash
| extend timestamp = TimeGenerated, IPEntity = IPAddress,  HostEntity = Computer, Algorithm = "SHA256", FileHash = tostring(FileHash)
| extend AccountName = tostring(split(Account, @'\')[1]), AccountDomain = tostring(split(Account, @'\')[0])
| extend InitiatingProcessAccount = Account
),
(DeviceFileEvents
| where SHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, 
InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, Type
| extend timestamp = TimeGenerated, HostEntity = DeviceName, AccountName = InitiatingProcessAccountName, AccountDomain = InitiatingProcessAccountDomain, 
Algorithm = "SHA256", FileHash = tostring(InitiatingProcessSHA256), CommandLine = InitiatingProcessCommandLine,Image = InitiatingProcessFolderPath
| extend InitiatingProcessAccount = strcat(AccountDomain, "\\", AccountName)
),
(DeviceImageLoadEvents
| where SHA256 has_any (sha256Hashes)
| project TimeGenerated, ActionType, DeviceId, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, 
InitiatingProcessId, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessSHA256, Type
| extend timestamp = TimeGenerated, HostEntity = DeviceName, AccountName = InitiatingProcessAccountName, AccountDomain = InitiatingProcessAccountDomain, 
Algorithm = "SHA256", FileHash = tostring(InitiatingProcessSHA256),  CommandLine = InitiatingProcessCommandLine,Image = InitiatingProcessFolderPath
| extend InitiatingProcessAccount = strcat(AccountDomain, "\\", AccountName)
),
(Event
| where Source =~ "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EvData = parse_xml(EventData)
| extend EventDetail = EvData.DataItem.EventData.Data
| extend Image = EventDetail.[4].["#text"],  CommandLine = EventDetail.[10].["#text"], Hashes = tostring(EventDetail.[17].["#text"])
| extend Hashes = extract_all(@"(?P<key>\w+)=(?P<value>[a-zA-Z0-9]+)", dynamic(["key","value"]), Hashes)
| extend Hashes = column_ifexists("Hashes", dynamic(["", ""])), CommandLine = column_ifexists("CommandLine", "")
| mv-expand Hashes
| where Hashes[0] =~ "SHA256" and Hashes[1] has_any (sha256Hashes)  
| project TimeGenerated, EventDetail, UserName, Computer, Type, Source, Hashes, CommandLine, Image
| extend Type = strcat(Type, ": ", Source)
| extend timestamp = TimeGenerated, HostEntity = Computer, AccountName = tostring(split(UserName, @'\')[1]), AccountUPNSuffix = tostring(split(UserName, @'\')[0]), FileHash = tostring(Hashes[1])
| extend InitiatingProcessAccount = UserName
)
)
| extend HostName = tostring(split(HostEntity, ".")[0]), DomainIndex = toint(indexof(HostEntity, '.'))
| extend HostNameDomain = iff(DomainIndex != -1, substring(HostEntity, DomainIndex + 1), HostEntity)
```