# Email-IOC-Extractor-v2

eioc2.py is an updated version of eioc.py created by MalwareCube. eioc2.py has additional functions such as homoglyph attack detection, phishing keyword search, and URL risk-level evaluation. The script is still in development, and I am going to add more automated checks to better evaluate email legitimacy automatically.

Link to the original tool: https://github.com/MalwareCube/Email-IOC-Extractor/tree/main

### Requirements
``` pip3 install -r requirements.txt ```

### Usage
``` python3 eioc2.py <file_path> ```

Example:
```
$ python3 eioc2.py file.eml 
Extracted IP Addresses:
====================================
213[.]227[.]154[.]65 - Lelystad, Flevoland, NL, ISP: AS60781 LeaseWeb Netherlands B.V.

Extracted URLs:
====================================
http://www[.]w3[.]org/TR/html4/loose[.]dtd

Extracted Headers:
====================================
Return-Path: <Paol.Reggiani@moss.it>
Authentication-Results: mailin004.protonmail.ch; dmarc=none (p=none dis=none)
 header.from=moss.it
From: Paolo Reggiani <Paol.Reggiani@moss.it>
To: wpx@protonmail.com
Subject: FW: Due Invoice Payment - protonmail.com - Wire Transfer Document
Date: 14 Jan 2020 00:06:05 -0800

Extracted Attachments:
====================================
Filename: quotation.iso
MD5: 6aef1d7f88e8aa450a0c604b4caee5ba
SHA1: 3fe45f8cd20cd7c63e55e3918dac1d3a0d7fb05a
SHA256: 75fdb848eac332b4ca7d88f497e7ba7ebbb9a798d825b28cf1f87b9d7149e87f


Email legitimacy auto-validation:
====================================
Homoglyph Attack Risk Level       : LOW
Sender Origin       : External!!!
Pattern Analysis       : Detected 1 keyword(s)   Risk Level: MEDIUM   Subject: 'FW: Due Invoice Payment - protonmail.com - Wire Transfer Document'
URLs Risk Level       :  MEDIUM
```
