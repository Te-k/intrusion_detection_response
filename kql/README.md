# KQL for Defender & Sentinel

This folder gather useful KQL queries and information along with knowledge on MS Defender and Sentinel.

KQL resources:
* https://www.kqlsearch.com/


## Load external resources

The [externaldata](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator?view=microsoft-fabric) operator can be used to load external sources, mostly as JSON, CSV or TXT files.

That's for instance how microsoft is often suggesting to search for IOCs based on IOC CSV files, like [here](https://github.com/Azure/Azure-Sentinel/blob/master/Detections/MultipleDataSources/EUROPIUM%20_September2022.yaml). Here is a shorter example from [Microsoft documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices):

```kql
let abuse_sha256 = (externaldata(sha256_hash: string)
[@"https://bazaar.abuse.ch/export/txt/sha256/recent/"]
with (format="txt"))
| where sha256_hash !startswith "#"
| project sha256_hash;
abuse_sha256
| join (EmailAttachmentInfo
| where Timestamp > ago(1d)
) on $left.sha256_hash == $right.SHA256
| project Timestamp,SenderFromAddress,RecipientEmailAddress,FileName,FileType,
SHA256,ThreatTypes,DetectionMethods
```

In some cases, you will need to convert the data table obtained from externaldata into an array, which you can do with project:

```kql
let malicious_extensions = (externaldata(extension_id: string)
[@"https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/refs/heads/main/malicious_extensions_detailed.csv"]
with (format="csv", ignoreFirstRecord=true));
let extensions_ids = (malicious_extensions | project extension_id);
DeviceFileEvents
| where FolderPath has_any (extensions_ids)
```

To read on this topic:
* [IOC hunting at scale](https://kqlquery.com/posts/ioc-hunting-at-scale/)
* [Exploring KQL: External Data Integration and Custom IOC Matching for Enhanced Threat](https://rodtrent.substack.com/p/exploring-kql-external-data-integration)