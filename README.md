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
 - LUA
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
In your `list_path` you can configure the following lists

### `asn.deny.lst`
List of literal Autonomous System Numbers to block 

E.g. 
```
AS3209
```
### `as_dscr.deny.lst`
List of [LUA Regular Expressions](https://www.lua.org/pil/20.2.html) of which `ipwhois` puts as `as_desc`. Which consists of the `as-name`, first line of `descr` and the CC when running WHOIS against the AS.

E.g. `whois AS3209`
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

Where a suitable regexp might be `VODANET.*`

### `as_cc.deny.lst`
List ISO 3166-2 country codes, associated to the Autonomous System. One per line.


# Bad Client Examples

https://www.hrz.uni-bonn.de/de/nachrichten/abruf-durch-unzulaessige-e-mail-clients-gesperrt