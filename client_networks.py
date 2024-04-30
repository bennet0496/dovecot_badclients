#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2024 Bennet Becker <dev@bennet.cc>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
from ipwhois import IPWhois
from ipwhois.utils import ipv4_is_defined
import sys
import json
from datetime import datetime
from typing import *
import socket
import struct


def find_net(ip: str, arr: Iterable[str]) -> str | None:
    packed_ip = socket.inet_aton(ip)
    ip_int = struct.unpack("!L", packed_ip)[0]
    for net_str in arr:
        net, mask = net_str.split("/")
        packed_net = socket.inet_aton(net)
        net_int = struct.unpack("!L", packed_net)[0]
        if net_int & (0xffffffff << (32 - int(mask))) == ip_int & (0xffffffff << (32 - int(mask))):
            return net_str
    return None


def main():
    if len(sys.argv) < 2:
        return
    ip = sys.argv[1]
    reserved = ipv4_is_defined(ip)
    if reserved[0]:
        data = {
            "asn": "None",
            "asn_country_code": "ZZ",
            "asn_description": "IANA-RESERVED",
            "net_name": reserved[1],
            "net_country_code": "ZZ",
            "entities": ["None"],
            "reserved": True
        }
        print(json.dumps(data))
    else:
        with (open("cache.json", "a+") as f):
            cache = {}
            f.seek(0)
            if f.read(2) != "":
                f.seek(0)
                cache = json.load(f)
            netw = find_net(ip, cache.keys())
            if netw is None or \
                    (cache[netw]["ts"] + (60 * 60 * 24)) < (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds():
                obj = IPWhois(ip)
                results = obj.lookup_rdap(depth=1)
                cache[results['asn_cidr']] = results
                cache[results['asn_cidr']]['ts'] = (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
            else:
                results = cache[netw]

            data = {
                "asn": "AS" + results['asn'],
                "asn_country_code": results['asn_country_code'] or "None",
                "asn_description": results['asn_description'],
                "net_name": results['network']['name'],
                "net_country_code": results['network']['country'] or "None",
                "entities": results['entities']
            }
            try:
                f.seek(0)
                f.truncate()
                json.dump(cache, f)
                print(json.dumps(data))
            except KeyboardInterrupt:
                f.seek(0)
                f.truncate()
                json.dump(cache, f)
                sys.exit(1)


if __name__ == "__main__":
    main()
