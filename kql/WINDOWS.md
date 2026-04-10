# Windows Detection

## Services

Service creations are logged in the `DeviceEvent` table:

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceName = todynamic(AdditionalFields)["ServiceName"]
```

## Named Pipes

Named pipe creation can be found in the `DeviceEvent` table under the action `NamedPipeEvent`, for instance:

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| extend FileOperation=parse_json(AdditionalFields)["FileOperation"]
| extend Pipename=parse_json(AdditionalFields)["PipeName"]
| where Pipename contains "IMpService"
// pipename in the format \Device\NamedPipe\Sfx
```

See the following rules:
* [Detects malicious SMB Named Pipes (used by common C2 frameworks)](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Command%20and%20Control/C2-NamedPipe.md)


