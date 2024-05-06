# Dovecot Bad Clients

There are popular mail clients that do nasty stuff when a user logs into them. Like routing communication through their servers or sync the credentials to their servers and letting the server retrieve mail on behalf of the user. This is a privacy nightmare and this script is meant to find users, using such clients and stopping them.

It hooks into Dovecot as a passdb, logging request denying it when the user logs in from a listed source. These listed sources can be
 - The Autonomous System if the requesting IP by its
   - Number (ASN)
   - Description/Name (according to its WHOIS entry)
   - Registration Country (according to its WHOIS entry)
 - The Network of requesting IP Address by
   - CIDR Network
   - Country (according to its WHOIS entry)
   - Name (according to its WHOIS entry)
 - The reverse hostname of the requesting IP
 - Entities related to the WHOIS entry like Organizations, Owners, Technical Contacts, Admin Contacts, etc...

### Future additions
In the future other information sources to consider could be
 - GeoIP to MaxMind DB or similar
 - Realtime DNS blocklists (RBL)

Feel free open an issue for additional ideas

## Setup
First you need to install the dovecot lua extension e.g. with
```bash
apt install dovecot-auth-lua
```
The package may be called differently depending on you distro

Then install the script dependencies with either system packaging tools like `apt` or via the language specific tools like `pip` and `luarocks`
 - Python
   - `ipwhois`
   - `iniconfig`
   - `portalocker`
 - Lua
   - `lua-socket`
   - `lua-json` (or `lua-cjson`)
   - `lua-inifile`

Put `login.lua` in `/etc/dovecot` and `client_networks.py` in `/usr/local/bin`.

Now configure the passdb in Dovecot like this
```
passdb {
  driver = lua
  args = file=/etc/dovecot/login.lua blocking=yes
  skip = never
}
```
Create a file `/etc/dovecot/bad_clients.conf.ext` to set up the paths for the scripts
```ini
list_path=/etc/dovecot/lists
asn_script_path=/usr/local/bin/client_networks.py
cachepath=/var/run/dovecot/whois_cache.json
```

## Set up the lists
In your `list_path` you can configure the following lists. No matter how you set up the list it will be impossible to block the following networks
 - `0.0.0.0/8` (This Network, RFC 1122, Section 3.2.1.3)
 - `127.0.0.0/8` (Loopback, RFC 1122, Section 3.2.1.3)
 - `169.254.0.0/16` (Link Local, RFC 3927)
 - `192.0.0.0/24` (IETF Protocol Assignments, RFC 5736)
 - `192.0.2.0/24` (TEST-NET-1, RFC 5737)
 - `192.88.99.0/24` (6to4 Relay Anycast, RFC 3068)
 - `198.18.0.0/15` (Network Interconnect Device Benchmark Testing, RFC 2544)
 - `198.51.100.0/24` (TEST-NET-2, RFC 5737)
 - `203.0.113.0/24` (TEST-NET-3, RFC 5737)
 - `224.0.0.0/4` (Multicast, RFC 3171)
 - `255.255.255.255/32` (Limited Broadcast, RFC 919, Section 7)
 - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (Private-Use Networks, RFC 1918)
 - `198.97.38.0/24` (IANA Reserved)

### `asn.deny.lst`
List of literal Autonomous System Numbers to block 

E.g. 
```
# Vodafone, DE
AS3209
```
### `as_dscr.deny.lst`
List of [Lua Regular Expressions](https://www.lua.org/pil/20.2.html) of which `ipwhois` puts as `as_desc`. Which consists of the `as-name`, first line of `descr` and the CC when running WHOIS against the AS.

`whois AS3209`
```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to 'AS3209 - AS3353'

as-block:       AS3209 - AS3353
descr:          RIPE NCC ASN block
remarks:        These AS Numbers are assigned to network operators in the RIPE NCC service region.
mnt-by:         RIPE-NCC-HM-MNT
created:        2018-11-22T15:27:19Z
last-modified:  2018-11-22T15:27:19Z
source:         RIPE

% Information related to 'AS3209'

% Abuse contact for 'AS3209' is 'abuse.de@vodafone.com'

aut-num:        AS3209
as-name:        VODANET
org:            ORG-MAT1-RIPE
descr:          International IP-Backbone of Vodafone
descr:          Duesseldorfer Strasse 15
descr:          D-65760 Eschborn
descr:          Germany
descr:          http://www.vodafone.de
```
Becomes `VODANET International IP-Backbone of Vodafone, DE`

Each line needs to be a valid Lua Regular expression that need to match the entire description e.g. `VODANET.*` or `.*Vodafone.*` for `VODANET International IP-Backbone of Vodafone, DE`

### `as_cc.deny.lst` and `net_cc.deny.lst`
List [ISO 3166-2 country codes](https://www.iso.org/iso-3166-country-codes.html), associated to the Autonomous System or Network. One per line.

| CC | Country                           | CC | Country                                    | CC | Country                                    | CC | Country                            |
|:--:|:----------------------------------|:--:|:-------------------------------------------|:--:|:-------------------------------------------|:--:|:-----------------------------------|
| `AD` | Andorra                           | `EG` | Egypt                                      | `LB` | Lebanon                                    | `RO` | Romania                            |
| `AE` | United Arab Emirates              | `EH` | Western Sahara                             | `LC` | Saint Lucia                                | `RS` | Serbia                             |
| `AF` | Afghanistan                       | `ER` | Eritrea                                    | `LI` | Liechtenstein                              | `RU` | Russian Federation                 |
| `AG` | Antigua & Barbuda                 | `ES` | Spain                                      | `LK` | Sri Lanka                                  | `RW` | Rwanda                             |
| `AI` | Anguilla                          | `ET` | Ethiopia                                   | `LR` | Liberia                                    | `SA` | Saudi Arabia                       |
| `AL` | Albania                           | `FI` | Finland                                    | `LS` | Lesotho                                    | `SB` | Solomon Islands                    |
| `AM` | Armenia                           | `FJ` | Fiji                                       | `LT` | Lithuania                                  | `SC` | Seychelles                         |
| `AN` | Netherlands Antilles              | `FK` | Falkland Islands (Malvinas)                | `LU` | Luxembourg                                 | `SD` | Sudan                              |
| `AO` | Angola                            | `FM` | Micronesia, Federated States Of            | `LV` | Latvia                                     | `SE` | Sweden                             |
| `AQ` | Antarctica                        | `FO` | Faroe Islands                              | `LY` | Libyan Arab Jamahiriya                     | `SG` | Singapore                          |
| `AR` | Argentina                         | `FR` | France                                     | `MA` | Morocco                                    | `SH` | St. Helena                         |
| `AS` | American Samoa                    | `GA` | Gabon                                      | `MC` | Monaco                                     | `SI` | Slovenia                           |
| `AT` | Austria                           | `GB` | United Kingdom                             | `MD` | Moldova, Republic Of                       | `SJ` | Svalbard & Jan Mayen Islands       |
| `AU` | Australia                         | `GD` | Grenada                                    | `ME` | Montenegro                                 | `SK` | Slovakia (Slovak Republic)         |
| `AW` | Aruba                             | `GE` | Georgia                                    | `MF` | Saint Martin                               | `SL` | Sierra Leone                       |
| `AX` | Aland Islands                     | `GF` | French Guiana                              | `MG` | Madagascar                                 | `SM` | San Marino                         |
| `AZ` | Azerbaijan                        | `GG` | Guernsey                                   | `MH` | Marshall Islands                           | `SN` | Senegal                            |
| `BA` | Bosnia & Herzegovina              | `GH` | Ghana                                      | `MK` | Macedonia, The Former Yugoslav Republic Of | `SO` | Somalia                            |
| `BB` | Barbados                          | `GI` | Gibraltar                                  | `ML` | Mali                                       | `SR` | Suriname                           |
| `BD` | Bangladesh                        | `GL` | Greenland                                  | `MM` | Myanmar                                    | `ST` | Sao Tome & Principe                |
| `BE` | Belgium                           | `GM` | Gambia                                     | `MN` | Mongolia                                   | `SV` | El Salvador                        |
| `BF` | Burkina Faso                      | `GN` | Guinea                                     | `MO` | Macau                                      | `SY` | Syrian Arab Republic               |
| `BG` | Bulgaria                          | `GP` | Guadeloupe                                 | `MP` | Northern Mariana Islands                   | `SZ` | Swaziland                          |
| `BH` | Bahrain                           | `GQ` | Equatorial Guinea                          | `MQ` | Martinique                                 | `TC` | Turks & Caicos Islands             |
| `BI` | Burundi                           | `GR` | Greece                                     | `MR` | Mauritania                                 | `TD` | Chad                               |
| `BJ` | Benin                             | `GS` | South Georgia & The South Sandwich Islands | `MS` | Montserrat                                 | `TF` | French Southern Territories        |
| `BM` | Bermuda                           | `GT` | Guatemala                                  | `MT` | Malta                                      | `TG` | Togo                               |
| `BN` | Brunei Darussalam                 | `GU` | Guam                                       | `MU` | Mauritius                                  | `TH` | Thailand                           |
| `BO` | Bolivia                           | `GW` | Guinea-Bissau                              | `MV` | Maldives                                   | `TJ` | Tajikistan                         |
| `BR` | Brazil                            | `GY` | Guyana                                     | `MW` | Malawi                                     | `TK` | Tokelau                            |
| `BS` | Bahamas                           | `HK` | Hong Kong                                  | `MX` | Mexico                                     | `TL` | Timor-Leste                        |
| `BT` | Bhutan                            | `HM` | Heard & Mc Donald Islands                  | `MY` | Malaysia                                   | `TM` | Turkmenistan                       |
| `BV` | Bouvet Island                     | `HN` | Honduras                                   | `MZ` | Mozambique                                 | `TN` | Tunisia                            |
| `BW` | Botswana                          | `HR` | Croatia (Hrvatska)                         | `NA` | Namibia                                    | `TO` | Tonga                              |
| `BY` | Belarus                           | `HT` | Haiti                                      | `NC` | New Caledonia                              | `TR` | Turkey                             |
| `BZ` | Belize                            | `HU` | Hungary                                    | `NE` | Niger                                      | `TT` | Trinidad & Tobago                  |
| `CA` | Canada                            | `ID` | Indonesia                                  | `NF` | Norfolk Island                             | `TV` | Tuvalu                             |
| `CC` | Cocos (Keeling) Islands           | `IE` | Ireland                                    | `NG` | Nigeria                                    | `TW` | Taiwan                             |
| `CD` | Congo, Democratic Republic Of The | `IL` | Israel                                     | `NI` | Nicaragua                                  | `TZ` | Tanzania, United Republic Of       |
| `CF` | Central African Republic          | `IM` | Isle Of Man                                | `NL` | Netherlands                                | `UA` | Ukraine                            |
| `CG` | Congo                             | `IN` | India                                      | `NO` | Norway                                     | `UG` | Uganda                             |
| `CH` | Switzerland                       | `IO` | British Indian Ocean Territory             | `NP` | Nepal                                      | `UM` | United States Minor Outlying Islands|
| `CI` | Cote D’Ivoire                     | `IQ` | Iraq                                       | `NR` | Nauru                                      | `US` | United States                      |
| `CK` | Cook Islands                      | `IR` | Iran (Islamic Republic Of)                 | `NU` | Niue                                       | `UY` | Uruguay                            |
| `CL` | Chile                             | `IS` | Iceland                                    | `NZ` | New Zealand                                | `UZ` | Uzbekistan                         |
| `CM` | Cameroon                          | `IT` | Italy                                      | `OM` | Oman                                       | `VA` | Holy See (Vatican City State)      |
| `CN` | China                             | `JE` | Jersey                                     | `PA` | Panama                                     | `VC` | Saint Vincent & The Grenadines     |
| `CO` | Colombia                          | `JM` | Jamaica                                    | `PE` | Peru                                       | `VE` | Venezuela, Bolivarian Republic Of  |
| `CR` | Costa Rica                        | `JO` | Jordan                                     | `PF` | French Polynesia                           | `VG` | Virgin Islands (British)           |
| `CU` | Cuba                              | `JP` | Japan                                      | `PG` | Papua New Guinea                           | `VI` | Virgin Islands (U.S.)              |
| `CV` | Cape Verde                        | `KE` | Kenya                                      | `PH` | Philippines                                | `VN` | Viet Nam                           |
| `CX` | Christmas Island                  | `KG` | Kyrgyzstan                                 | `PK` | Pakistan                                   | `VU` | Vanuatu                            |
| `CY` | Cyprus                            | `KH` | Cambodia                                   | `PL` | Poland                                     | `WF` | Wallis & Futuna Islands            |
| `CZ` | Czech Republic                    | `KI` | Kiribati                                   | `PM` | St. Pierre & Miquelon                      | `WS` | Samoa                              |
| `DE` | Germany                           | `KM` | Comoros                                    | `PN` | Pitcairn                                   | `YE` | Yemen                              |
| `DJ` | Djibouti                          | `KN` | Saint Kitts & Nevis                        | `PR` | Puerto Rico                                | `YT` | Mayotte                            |
| `DK` | Denmark                           | `KP` | Korea, Democratic People’S Republic Of     | `PS` | Palestinian Territory                      | `ZA` | South Africa                       |
| `DM` | Dominica                          | `KR` | Korea, Republic Of                         | `PT` | Portugal                                   | `ZM` | Zambia                             |
| `DO` | Dominican Republic                | `KW` | Kuwait                                     | `PW` | Palau                                      | `ZW` | Zimbabwe                           |
| `DZ` | Algeria                           | `KY` | Cayman Islands                             | `PY` | Paraguay                                   | `ZZ` | Local Country                      |
| `EC` | Ecuador                           | `KZ` | Kazakhstan                                 | `QA` | Qatar                                      |    |                                    |
| `EE` | Estonia                           | `LA` | Lao People’S Democratic Republic           | `RE` | Reunion                                    |    |                                    |

`whois 139.162.133.252`
```
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See https://apps.db.ripe.net/docs/HTML-Terms-And-Conditions

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to '139.162.0.0 - 139.162.255.255'

% Abuse contact for '139.162.0.0 - 139.162.255.255' is 'abuse@linode.com'

inetnum:        139.162.0.0 - 139.162.255.255
netname:        EU-LINODE-20141229
descr:          139.162.0.0/16
org:            ORG-LL72-RIPE
country:        US
admin-c:        TA2589-RIPE
abuse-c:        LAS85-RIPE
tech-c:         TA2589-RIPE
status:         LEGACY
remarks:        Please send abuse reports to abuse@linode.com
mnt-by:         linode-mnt
created:        2004-02-02T16:20:09Z
last-modified:  2022-12-12T21:26:29Z
source:         RIPE
```
Is Network CC `US` but the associated AS, `AS63949` would have (interestingly enough) `NL` (which makes little sense, but this what `ipwhois` detects)

### `net_name.deny.lst`
List of [Lua regexes](https://www.lua.org/pil/20.2.html) of provider specified network names in WHOIS. 

Names might be `EU-LINODE-20141229`, `DE-D2VODAFONE-20220628`, `DTAG-DIAL16` or `AMAZON-IAD`, `MSFT`

These are not necessarily unique.

Each line needs to be a valid Lua Regular expression that need to match the entire name like `EU%-LINODE%-20141229` or `.*LINODE.*` for `EU-LINODE-20141229`

### `rev_host.deny.lst`
List of [Lua regexes](https://www.lua.org/pil/20.2.html) of reverse hostnames resolvable via the local DNS resolver.

E.g.
```
$ nslookup 52.23.158.188
188.158.23.52.in-addr.arpa	name = ec2-52-23-158-188.compute-1.amazonaws.com.
```
Empty (NXDOMAIN) results will be matched as `<>`
```
$ nslookup 52.97.246.245
** server can't find 245.246.97.52.in-addr.arpa: NXDOMAIN
```
Each line needs to be a valid Lua Regular expression that need to match the entire reverse name (without trailing dots), e.g. `.*%.compute%-1%.amazonaws%.com` for `ec2-52-23-158-188.compute-1.amazonaws.com`

### `entity.deny.lst`
List of [Lua regexes](https://www.lua.org/pil/20.2.html) of related WHOIS entities like administrators or organizations.

E.g. Related with `176.112.169.192` (ASN 7764) are `EY1327-RIPE` (VK admin-c), `ORG-LLCn4-RIPE` (VK LLC), `RIPE-NCC-END-MNT` (RIPE Contact), `VKCOMPANY-MNT` (Maintainer for VK objects), `VKNC` (VK admin-c), `MAIL-RU` (abuse-c)

### `ip_net.deny.lst`
List of IPv4 CIDR networks to block access from. E.g. `176.112.168.0/21`

There is no check for set host-bits, the mask is just applied to both addresses to compare network addresses, if they match the request is blocked. This means for example `176.112.170.0/21` is equivalent to `176.112.168.0/21`

## Logs
The script additionally generates log lines like this for later eximination
```
Mai 01 04:06:34 honeypot dovecot[56359]: auth-worker(61890): mail-audit: user=<honey-craig>, service=imap, ip=176.112.169.218, host=rimap26.i.mail.ru, asn=AS47764, as_cc=RU, as_desc=<VK-AS, RU>, net_name=<VK-FRONT>, net_cc=RU, entity=EY1327-RIPE, entity=ORG-LLCn4-RIPE, entity=RIPE-NCC-END-MNT, entity=VKCOMPANY-MNT, entity=VKNC, entity=MAIL-RU
Mai 03 13:07:45 honeypot dovecot[70754]: auth-worker(77223): mail-audit: user=<honey>, service=imap, ip=172.17.1.204, host=dhcp204.internal, asn=None, as_cc=ZZ, as_desc=<IANA-RESERVED>, net_name=<Private-Use Networks>, net_cc=ZZ, entity=None
Mai 06 04:20:25 honeypot dovecot[70754]: auth-worker(90054): mail-audit: user=<honey-sugar>, service=imap, ip=139.162.133.252, host=node-eu-0001.email2-cloud.com, asn=AS63949, as_cc=NL, as_desc=<AKAMAI-LINODE-AP Akamai Connected Cloud, SG>, net_name=<EU-LINODE-20141229>, net_cc=US, entity=linode-mnt, entity=ORG-LL72-RIPE, entity=TA2589-RIPE, entity=LAS85-RIPE
Mai 06 11:00:20 honeypot dovecot[91279]: auth-worker(92237): mail-audit: user=<honey-gmail-pop>, service=pop3, ip=209.85.218.15, host=mail-ej1-f15.google.com, asn=AS15169, as_cc=US, as_desc=<GOOGLE, US>, net_name=<GOOGLE>, net_cc=None, entity=GOGL
Mai 06 11:05:24 honeypot dovecot[91279]: auth-worker(92256): mail-audit: user=<honey-gmail-smtp>, service=smtp, ip=209.85.218.53, host=mail-ej1-f53.google.com, asn=AS15169, as_cc=US, as_desc=<GOOGLE, US>, net_name=<GOOGLE>, net_cc=None, entity=GOGL
```

A script to retrieve user statisics of the last 24h might look something like this
```bash
journalctl -S "24 hours ago" -g "mail-audit" | awk -F : '{print $6}' | sort | uniq -c | sort -h
```

## Integration Other Services
Mail ecosystems usually don't only consist of IMAP (or POP) servers, but have SMTP components for users to send emails as well. While it is possible for dovecot to act as an MUA, it is not a very common setup. Dedicated SMTP server like Exim or Postfix are probably used much more often. If these use SASL authentication with dovecot, they (at least Exim) will integrate flawlessly, showing up as `service=smtp` with the appropriate client IP address of the client connecting to SMTP.

In other setups and with other IMAP servers the script will currently not work.

# Bad Client Examples
Here are some example of clients and services worth blocking. Inspired by a [list of prohibited mail client at Uni Bonn](https://www.hrz.uni-bonn.de/de/nachrichten/abruf-durch-unzulaessige-e-mail-clients-gesperrt), because the clients more or less silently and transparently funnel credentials and/or messages through their clouds

**Mail Clients connecting via the cloud**
- New Outlook (Microsoft Corporation)
  - [Windows](https://www.microsoft.com/store/productId/9NRX63209R7B?ocid=pdpshare), macOS (with Cloud sync enabled)
  - [Privacy Policy](https://privacy.microsoft.com/en-us/privacystatement)
  - Login and Messages Synced with Office 365 Cloud to "enhance experience"
  - [IP Rages available](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide)
    - 13.107.6.152/31, 13.107.18.10/31, 13.107.128.0/22, 23.103.160.0/20, 40.96.0.0/13, 40.104.0.0/15, 52.96.0.0/14, 131.253.33.215/32, 132.245.0.0/16, 150.171.32.0/22, 204.79.197.215/32
- Edison Mail
  - Windows, [Android](https://play.google.com/store/apps/details?id=com.easilydo.mail)
  - [Privacy Policy](https://edisonmail.com/privacy)
  - Syncs locally but occasionally also logs in from AWS EC2 instances
  - [AWS IP Ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
  - AS14818 (AMAZON-AES) and maybe others
- Newton (CloudMagic, Inc.)
  - [Android](https://play.google.com/store/apps/details?id=com.cloudmagic.mail)
  - [Privacy Policy](https://newtonhq.com/k/privacypolicy)
  - Syncs via AWS EC2 instances
- Spark Mail 
  - [Android](https://play.google.com/store/apps/details?id=com.readdle.spark), macOS, iOS, [Windows](https://apps.microsoft.com/store/detail/XPFCS9QJBKTHVZ?ocid=pdpshare)
  - [Privacy Policy](https://sparkmailapp.com/legal/privacy-app)
  - Syncs locally and via GCE
  - [Google Cloud Ranges available](https://www.gstatic.com/ipranges/cloud.json)
  - AS396982 (GOOGLE-CLOUD-PLATFORM, US)
- Email App for Outlook & others, Email App for Yahoo! & others, Univeral Email and other derivatives of Mail.ru (Craigpark Limited/Mail.ru Group)
  - Android [[1]](https://play.google.com/store/apps/details?id=park.outlook.sign.in.client) [[2]](https://play.google.com/store/apps/details?id=park.yahoo.sign.in.app) [[3]](https://play.google.com/store/apps/details?id=park.hotm.email.app) [[4]](https://play.google.com/store/apps/details?id=ru.mail.mailapp)
  - Privacy Policy: [Craigpark Limited](https://docs.google.com/document/d/e/2PACX-1vT75n625hDx7EANwxBtTYS5hZGAEVKDAjOOCdhuY3oqoj4w84r2xkSXVq08-yCwY6D49Kja58R57qdS/pub?mp=android&mmp=mail), [Mail.ru](https://help.mail.ru/legal/terms/mail?mp=android&mmp=mail)
  - hardly functional
  - logs in via VK Networks from Moscow, even if App setup fails
  - AS47764 (VKCOMPANY-MNT) and maybe others
- Sugar Mail email app (Kostya Vasilyev US)
  - [Android](https://play.google.com/store/apps/details?id=org.kman.email2)
  - [Privacy Policy](https://sugarmail.app/privacy.html)
  - Logins via Linode VPSs
  - AS63949 (Akamai Connected Cloud (Linode LLC)) and maybe others 
  - [Linode IP Ranges](https://geoip.linode.com/)

**Services that allow to connect external accounts**
- GMail web ["Check Mail for other Accounts"](https://support.google.com/mail/answer/21289?ctx=gmail&hl=en&authuser=1) & ["Send mail as"](https://support.google.com/mail/answer/22370?hl=en-GB&sjid=4857229840897368681-EU#null)
  - Hostname: `mail%-.+%-.+%.google%.com`
  - POP3, SMTP
  - ASN 15169 (GOOGLE, US)
- [Protonmail "Import via Easy Switch"](https://proton.me/easyswitch)
  - Hostname: `%d+%-%d+%-%d+%-%d+%.protonmail%.ch`
  - IMAP
  - ASN 62371 (PROTON, CH)

**Mail Apps with suspicious wording or behavior**
- Boxer (vmWare Workspace ONE)
  - "Data collected by Boxer [...] User informatiton [...] such as [...] credentials"
  - [<img src="https://github.com/bennet0496/dovecot_badclients/assets/4955327/312ccb1e-6456-4203-8793-a2b1a2145803" height="300"/>](https://github.com/bennet0496/dovecot_badclients/assets/4955327/312ccb1e-6456-4203-8793-a2b1a2145803)
- MailTime
  - [Privacy Policy](https://mailtime.com/en/privacy)
  - "With your permission at sign-up or use of the MailTime App, you authorize us to access and process email messages in your Connected Email Accounts in order to provide the MailTime App Services to you"
- VK Mail
  - Likely the same as Mail.ru if it was working

## Cloud Rages to block
- [Office 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide)
- [Azure](https://www.microsoft.com/en-gb/download/details.aspx?id=56519)
- [AWS](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- [Google Could Compute](https://www.gstatic.com/ipranges/cloud.json)
- [Linode](https://geoip.linode.com/)
