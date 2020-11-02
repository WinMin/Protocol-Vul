# Protocol-vul
Vulnerabilities in some protocols are collected.

## Related Resources

[网络通讯协议图.pdf](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/44f73170-746e-4304-9d95-0cf2af3c48bf/.pdf)

## UPNP(Universal Plug and Play)

| ID/Alias                       | Description                                                  | References                                                   |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2017-17215                 | Huawei HG532 with some customized versions has a remote code execution vulnerability. An authenticated attacker could send malicious packets to port 37215 to launch attacks. Successful exploit could lead to the remote execution of arbitrary code. | [Huawei HG532 系列路由器远程命令执行漏洞分析](https://paper.seebug.org/490/) |
| CVE-2020-12695<br>CallStranger | The CallStranger vulnerability that is found in billions of UPNP devices can be used to exfiltrate data (even if you have proper DLP/border security means) or scan your network or even cause your network to participate in a DDoS attack.The vulnerability – CallStranger – is caused by Callback header value in UPnP SUBSCRIBE function can be controlled by an attacker and enables an SSRF-like vulnerability which affects millions of Internet facing and billions of LAN devices. | [CallStranger](https://github.com/yunuscadirci/CallStranger) |



## PPP(Point-to-Point Protocol)

| ID/Alias      | Description                                                  | References                                                   |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2020-8597 | a buffer overflow vulnerability in pppd due to a logic flaw in the packet processor of the [Extensible Authentication Protocol](https://tools.ietf.org/html/rfc2284) (EAP). An unauthenticated, remote attacker who sends a specially crafted EAP packet to a vulnerable PPP client or server could cause a denial-of-service condition or gain arbitrary code execution. | [Exploiting CVE-2020–8597](https://medium.com/apple-developer-academy-federico-ii/exploiting-cve-2020-8597-119c645c0699) |



## SLP(Service Location Protocol)

| ID/Alias      | Description                                                  | References |
| ------------- | ------------------------------------------------------------ | ---------- |
| CVE-2019-5544 | The vulnerability is due to a heap overwrite issue in OpenSLP used in ESXi and Horizon DaaS appliances. Malicious users with access to port 427 on the ESXi host or any Horizon DaaS platform through the network may overwrite the heap of the OpenSLP service, eventually causing remote code execution. |            |



## AFP(Apple Filing Protocol)

| ID/Alias      | Description                                                  | References                                                   |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2018-1160 | Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution. | [Exploiting an 18 Year Old Bug](https://medium.com/tenable-techblog/exploiting-an-18-year-old-bug-b47afe54172)<br>[Netatalk CVE-2018–1160 越界写漏洞分析](https://xz.aliyun.com/t/3710) |



## BlueTooth

| ID/Alias                  | Description                                                  | References                                                   |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2020-0022<br>BlueFrag | In reassemble_and_dispatch of packet_fragmenter.cc, there is possible out of bounds write due to an incorrect bounds calculation. This could lead to remote code execution over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation. | [CVE-2020-0022 an Android 8.0-9.0 Bluetooth Zero-Click RCE – BlueFrag](https://insinuator.net/2020/04/cve-2020-0022-an-android-8-0-9-0-bluetooth-zero-click-rce-bluefrag/) |
| CVE-2020-10135<br>BIAS    | Legacy pairing and secure-connections pairing authentication in Bluetooth® BR/EDR Core Specification v5.2 and earlier may allow an unauthenticated user to complete authentication without pairing credentials via adjacent access. An unauthenticated, adjacent attacker could impersonate a Bluetooth BR/EDR master or slave to pair with a previously paired remote device to successfully complete the authentication procedure without knowing the link key. | [BIAS](https://francozappa.github.io/about-bias/)            |
| CVE-2019-9506<br>KNOB     | The specification of Bluetooth includes an encryption key negotiation protocol that allows to negotiate encryption keys with 1 Byte of entropy without protecting the integrity of the negotiation process. A remote attacker can manipulate the entropy negotiation to let any standard compliant Bluetooth device negotiate encryption keys with 1 byte of entropy and then brute force the low entropy keys in real time. | [KNOB Attack](https://knobattack.com/)                       |
| BleedingTooth             | Potential security vulnerabilities in BlueZ may allow escalation of privilege or information disclosure. BlueZ is releasing Linux kernel fixes to address these potential vulnerabilities. | [CVE-2020-12351](https://github.com/google/security-research/security/advisories/GHSA-h637-c88j-47wq)<br>[CVE-2020-12352](https://github.com/google/security-research/security/advisories/GHSA-7mh3-gq28-gfrq)<br>[CVE-2020-24490](https://github.com/google/security-research/security/advisories/GHSA-ccx2-w2r4-x649) |



## SMB(Server Message Block)

| ID/Alias                  | Description                                                  | References                                                   |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| MS17-010<br>EternalBlue   | EternalBlue (patched by Microsoft via [MS17-010](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)) is a security flaw related to how a Windows SMB 1.0 (SMBv1) server handles certain requests. If successfully exploited, it can allow attackers to execute arbitrary code in the target system. | [MS17-010](https://github.com/worawit/MS17-010.git)          |
| CVE-2020-0796<br>SMBGhost | A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability. | [CVE-2020-0796 Remote Code Execution POC](https://github.com/ZecOps/CVE-2020-0796-RCE-POC)<br>[SMBGhost_RCE_PoC](https://github.com/chompie1337/SMBGhost_RCE_PoC) |



## CPD(Cisco Discovery Protocol)

| ID/Alias | Description                                                  | References                                                   |
| -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CDPwn    | Armis labs discovered 5 zero day vulnerabilities affecting a wide array of Cisco products, including Cisco routers, switches, IP Phones and IP cameras. Four of the vulnerabilities enable Remote Code Execution (RCE). The latter is a Denial of Service (DoS) vulnerability that can halt the operation of entire networks. | [Armis-CDPwn-WP](https://go.armis.com/hubfs/White-papers/Armis-CDPwn-WP.pdf) |

## TCP/IP

| ID/Alias                       | Description                                                  | References                                                   |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Urgent11                       | The Urgent11 security flaws reside in the TCP/IP (IPnet) networking stack, which is a component of the VxWorks RTOS that manages the device's ability to connect to the internet or to other devices on a local network. | [Urgent11 Technical White Paper]([https://info.armis.com/rs/645-PDC-047/images/Urgent11%20Technical%20White%20Paper.pdf](https://info.armis.com/rs/645-PDC-047/images/Urgent11 Technical White Paper.pdf)) |
| CVE-2020-11896<br>Ripple20     | CVE-2020-11896 is a critical vulnerability in Treck TCP/IP stack. It allows for Remote Code execution by any attacker that can send UDP packets to an open port on the target device. A prerequisite of this vulnerability is that the device supports IP fragmentation with IP tunneling. In some of the cases where this prerequisite is not met, there will remain a DoS vulnerability. | [JSOF_Ripple20_Technical_Whitepaper_June20](https://www.jsof-tech.com/wp-content/uploads/2020/06/JSOF_Ripple20_Technical_Whitepaper_June20.pdf) |
| CVE-2020-16898<br>Bad Neighbor | A remote code execution vulnerability exists when the Windows TCP/IP stack improperly handles ICMPv6 Router Advertisement packets that use Option Type 25 (Recursive DNS Server Option) and a length field value that is even. | [CVE-2020-16898: “Bad Neighbor”](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/cve-2020-16898-bad-neighbor/) |



## Thunderbolt

| ID/Alias   | Description                                                  | References                           |
| ---------- | ------------------------------------------------------------ | ------------------------------------ |
| Thunderspy | Thunderspy targets devices with a Thunderbolt port. If your computer has such a port, an attacker who gets brief physical access to it can read and copy all your data, even if your drive is encrypted and your computer is locked or set to sleep. | [thunderspy](https://thunderspy.io/) |



## SNMP(Simple Network Management Protocol)

| ID/Alias      | Description                                                  | References                                                   |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2017-6736 | The Simple Network Management Protocol (SNMP) subsystem of Cisco IOS 12.0 through 12.4 and 15.0 through 15.6 and IOS XE 2.2 through 3.17 contains multiple vulnerabilities that could allow an authenticated, remote attacker to remotely execute code on an affected system or cause an affected system to reload. An attacker could exploit these vulnerabilities by sending a crafted SNMP packet to an affected system via IPv4 or IPv6. Only traffic directed to an affected system can be used to exploit these vulnerabilities. The vulnerabilities are due to a buffer overflow condition in the SNMP subsystem of the affected software. | [CVE-2017-6736 思科IOS系统远程代码执行漏洞分析](https://www.anquanke.com/post/id/98225) |



## WLAN

| ID/Alias                  | Description                                                  | References                                                   |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2019-10539<br>Qualpwn | Possible buffer overflow issue due to lack of length check when parsing the extended cap IE header length. | [QualPwn - Exploiting Qualcomm WLAN and Modem Over The Air](https://blade.tencent.com/en/advisories/qualpwn/) |
| CVE-2019-11151            | Memory corruption issues in Intel(R) WIFI Drivers before version 21.40 may allow a privileged user to potentially enable escalation of privilege, denial of service, and information disclosure via local access. | [ANALYZING A TRIO OF REMOTE CODE EXECUTION BUGS IN INTEL WIRELESS ADAPTERS](https://www.zerodayinitiative.com/blog/2020/5/4/analyzing-a-trio-of-remote-code-execution-bugs-in-intel-wireless-adapters) |
| CVE-2019-15126<br>Kr00k   | is a vulnerability in Broadcom and Cypress Wi-Fi chips that allows unauthorized decryption of some WPA2-encrypted traffic. | [Wi-Fi WPA2 “Kr00k”窃密漏洞分析与复现](https://www.secrss.com/articles/18174) |





## IPP (Internet Printing Protocol)

| ID/Alias      | Description                                                  | References |
| ------------- | ------------------------------------------------------------ | ---------- |
| CVE-2019-8675 | Stephan Zeisberg discovered that the CUPS SNMP backend incorrectly handled encoded ASN.1 inputs. A remote attacker could possibly use this issue to cause CUPS to crash by providing specially crafted network traffic. |            |



## LoRaWAN

| ID/Alias | Description                                                  | References                                                   |
| -------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| loradawn | LoRaDawn is a series of vulnerabilities in LoRaWAN discovered by Tencent Blade Team that can cause Remote Denial of service of LoRaWAN node and potential code execution of LoRaWAN gateway under certain conditions.As a well-known LoRaWAN protocol stack, LoRaMac-Node is widely used in nodes and modules of LoRaWAN vendors.[CVE-2020-11068 ](https://github.com/Lora-net/LoRaMac-node/security/advisories/GHSA-559p-6xgm-fpv9)  LoRaMac, [CVE-2020-4060](https://github.com/lorabasics/basicstation/security/advisories/GHSA-v9ph-r496-4m2j) LoRa Basics™ Station | [LoRaDawn - Multiple LoRaWAN Security Vulnerabilities](https://blade.tencent.com/en/advisories/loradawn/) |



## DNS

| ID/Alias                | Description                                                  | References                                                   |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| CVE-2020-1350<br>SIGRed | a wormable, critical vulnerability (CVSS base score of 10.0) in the Windows DNS server that affects Windows Server versions 2003 to 2019, and can be triggered by a malicious DNS response. As the service is running in elevated privileges (SYSTEM), if exploited successfully, an attacker is granted Domain Administrator rights, effectively compromising the entire corporate infrastructure. | [SIGRed – Resolving Your Way into Domain Admin: Exploiting a 17 Year-old Bug in Windows DNS Servers](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/)<br>[CVE-2020-1350 (SIGRed) - Windows DNS DoS Exploit](https://github.com/maxpl0it/CVE-2020-1350-DoS/blob/master/sigred_dos.py) |



# Contributor
* [swing](https://github.com/WinMin)

* [leommxj](https://github.com/leommxj)