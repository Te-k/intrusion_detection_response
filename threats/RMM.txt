# RMM

Resources on detection:

* [RMM Detection](https://gist.github.com/brokensound77/6d8a1e480e65ff20e151099c98267b14)
* https://lolrmm.io/
* [RemoteManagementMonitoringTools](https://github.com/jschell/RemoteManagementMonitoringTools/tree/main)

## RMM Solutions

### AnyDesk

Examples of malicious usage of AnyDesk:
* March 2026: [Attack Targeting MS‑SQL Servers to Deploy the ICE Cloud Scanner (Larva-26002)](https://asec.ahnlab.com/en/92988/)
* September 2025: [MostereRAT Deployed AnyDesk/TightVNC for Covert Full Access](https://www.fortinet.com/blog/threat-research/mostererat-deployed-anydesk-tightvnc-for-covert-full-access)

Installation path:
* `C:\Program Files (x86)\AnyDesk\*`
* `/Applications/AnyDesk.app`
* `C:\Program Files\AnyDesk\*`

Signature:
* Name: philandro Software GmbH
* Status: Valid
* Issuer: DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
* Valid from: 12:00 AM 12/13/2021
* Valid to: 11:59 PM 01/08/2025
* Valid usage: Code Signing
* Algorithm: sha256RSA
* Thumbprint: 9CD1DDB78ED05282353B20CDFE8FA0A4FB6C1ECE
* Serial number: 0D BF 15 2D EA F0 B9 81 A8 A9 38 D5 3F 76 9D B8

Network indicators:
* `anyDesk.com`
* `api.playanext.com`

See [here](https://lolrmm.io/tools/anydesk) or [here](https://github.com/jschell/RemoteManagementMonitoringTools/blob/main/RMM/AnyDesk/RMM_Summary_AnyDesk.md)

## Detection

Detection in Defender can be done either through DeviceProcesssEvents, DeviceFileEvents, or DeviceFileCertificateInfo.

### Detection through certificate

This detection should be harder to circumvent as file names and path can change:

```kql
let signers = dynamic(["ZOHO Corporation Private Limited", "Superops Inc", "NinjaRMM", "Atera Networks", "Action1", "AeroAdmin", 
"Teknopars Bilisim", "TEKNOPARS BİLİŞİM", "Ammyy", "anydesk software", "philandro software", "AOMEI International Network Limited",
"Anyplace Control Software", "Honcharuk Yuriy", "Yuriy Honcharuk", "Yurii Honcharuk", "aweray limited", "aweray pte. ltd.",
"Barracuda Networks","BeamYourScreen GmbH", "Mikogo GmbH", "ConnectWise", "CONTINUUM MANAGED", "ScreenConnect", "CrossTec", 
"NetSupport", "DWSNET OÜ", "DameWare Development", "Datto Inc", "NCH Software", "German Gorodokuplya", "FleetDeck", "Point B Ltd",
"ISL Online", "XLAB D.O.O.", "Enter Srl", "Enter S.R.L.", "JumpCloud", "Level Software, Inc", "Yakhnovets Denis Aleksandrovich IP",
"MSPBytes", "Trichilia Consultants", "meshcentral", "N-Able Technologies", "LogicNow", "naverisk", "NavMK1 Limited", "NetSupport", 
"CrossTec", "Bravura Software LLC", "PDQ.com", "Panorama9", "pcvisit software ag", "MMSoft Design", "famatech", "realvnc", "idrive",
"Remote Utilities", "Projector.is, Inc.", "Krämer IT Solutions GmbH", "ShowMyPC", "SimpleHelp Ltd", "Nanosystems S.R.L.",
"Servably, Inc.", "O&O Software GmbH", "TSplus", "Remote Access World", "JWTS", "AmidaWare", "Tactical Techs", "TeamViewer",
"TechInline", "Duc Fabulous", "XMReality", "Xeox", "hs2n Informationstechnologie GmbH", "Zoho", "Parsec Cloud",
"TrustConnect Software PTY LTD"]); // Partial list established from resources above
DeviceFileCertificateInfo
| where Signer has_any (signers)
```