# Blue Hammer

Blue Hammer is a privilege escalation in Windows 10/11 that was publicly dropped on Github on April 2nd, seemingly because of the heavy and frustrating reporting process to Microsoft:

* [Github repo](https://github.com/Nightmare-Eclipse/BlueHammer)
* [Blog post](https://deadeclipse666.blogspot.com/2026/04/public-disclosure.html)

Analysis:
* [BlueHammer: Inside the Windows Zero-Day That Turns Defender Against Itself](https://www.cyderes.com/howler-cell/windows-zero-day-bluehammer)

Detection rules:
* One KQL rule [here](https://github.com/SlimKQL/Detections.AI/blob/main/KQL/defenderxdr-bluehammer-detection.kql)
* Yara and SIGMA [here](https://github.com/technoherder/BlueHammerFix/tree/main/detection_rules)

My translation of the SIGMA rules above to KQL are in this folder.



