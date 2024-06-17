#!/usr/bin/env python3

import re
import sys
from collections import Counter

KNOWN_GOOD_ASNS = [
    "AS680",    # DFN
    "AS207592", # GWDG
    "AS2200",   # Réseau national de télécommunications pour la technologie, l'enseignement et la recherche (EDU ISP)
    "AS56166",  # Indian Institute of Science Education and Research Bhopal
    "AS1835",   # FSKNET-DK Forskningsnettet - Danish network for Research and Education
    "AS3320",   # DTAG/Deutsche Telekom
    "AS204445", # DB WiFi
    "AS8447",   # A1 Telekom Austria
    "AS29580",  # A1 Bulgaria
    "AS8717",   # A1 Bulgaria
    "AS21928",  # t-mobile US
    "AS13036",  # t-mobile CZ
    "AS3215",   # France Telecom, Orange
    "AS9121",    # Türk Telekomünikasyon Anonim Şirketi
    "AS8881",   # VERSATEL/1&1
    "AS3209",   # Vodafone DE
    "AS12430",  # Vodafone ES
    "AS6805",   # Telefonica/O2 DE
    "AS3352",   # Telefonica ES
    "AS5610",   # O2 CZ
    "AS16202",  # Telecolumbus/Pÿur
    "AS20676",  # Plusnet https://www.plusnet.de/
    "AS60294",  # Deutsche Glasfaser
    "AS7922",   # Comcast US
    "AS15600",  # Quickline CH
    "AS12874",  # Fastweb IT
    "AS51207",  # Free Mobile SAS, FR
    "AS54004",  # Optimum WiFi US
]
KNOWN_DNS_SUFF = [
    "mpg.de",
    "pool.telefonica.de",
    "dynamic.kabel-deutschland.de",
    "dip0.t-ipconnect.de",
    "customers.d1-online.com",
    "versanet.de",
    "dyn.pyur.net",
    "web.vodafone.de",
    "cam.ac.uk",
]

AS_COMMENTS = {
    "AS212238": "Commercial VPN", # CDNEXT, GB -> NordVPN/ProtonVPN
    "AS60068": "Commercial VPN", # CDN77 _, GB -> NordVPN/ProtonVPN
    "AS14618": "Commercial VPN or Bad App",
    "AS786": "Cambridge University",
    "AS44407": "Business ISP"
}


def main(argv):
    global KNOWN_GOOD_ASNS
    global KNOWN_DNS_SUFF
    global AS_COMMENTS
    data = list()
    with open(argv[1], "r") as f:
        for line in f.readlines():
            pattern = re.compile(
                "[A-Za-z]{3,3} [0-9]{2,2} [0-9:]{8,8} idefix dovecot\[[0-9]+\]: auth-worker\([0-9]+\): mail-audit: user=<(.+)>, service=(.+?), ip=(.+?), host=(.+?), asn=(.+?), as_cc=(.+?), as_desc=<(.+?)>, net_name=<(.+?)>, net_cc=(.+?), (entity=.*)")
            match = pattern.match(line)
            if match:
                entry = match.groups()
                entites = list()
                blocked = False
                matched = None
                for field in entry[9].split(","):
                    if str(field).strip().startswith("entity="):
                        entites.append(field[len("entity="):].strip("="))
                    elif str(field).strip().startswith("blocked="):
                        blocked = True
                        # print(entry)
                    elif str(field).strip().startswith("matched="):
                        matched = field[len("matched="):].strip("=")
                data.append({
                    "user": entry[0],
                    "service": entry[1],
                    "ip_net": entry[2],
                    "rev_host": entry[3],
                    "asn": entry[4],
                    "as_cc": entry[5],
                    "as_desc": entry[6],
                    "net_name": entry[7],
                    "net_cc": entry[8],
                    "entities": entites,
                    "blocked": blocked,
                    "matched": matched
                })
        print("Blocked users:")
        bu = set([e["user"] for e in data if e["blocked"]])
        for u in bu:
            print(" {} ({})".format(u, ", ".join(
                set(["{}:{}".format(e["matched"], e[e["matched"]]) for e in data if e["blocked"] and e["user"] == u]))))

        def suffixes(str):
            arr = str.split(".")
            suf = []
            for _ in range(len(arr)):
                suf.append(".".join(arr))
                arr.pop(0)
            return suf

        new_ips = Counter([
            "{0} {1}".format(
                ((e["blocked"] and "!" or "") + e["ip_net"]).ljust(16, ' '),
                e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(e["as_desc"][:30] + (e["as_desc"][30:] and ".."))
            ) for e in data if len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) == 0 and e["asn"] not in KNOWN_GOOD_ASNS])
        new_asn = Counter(
            ["{} {} {}".format(
                ((e["blocked"] and "!" or "") + e["asn"]).ljust(10, ' '),
                e["as_desc"],
                (e["asn"] in AS_COMMENTS.keys() and "({})".format(AS_COMMENTS[e["asn"]]) or "")
            ) for e in data if e["asn"].strip() not in KNOWN_GOOD_ASNS])

        old_ips = Counter([
            "{0} {1}".format(
                ((e["blocked"] and "!" or "") + e["ip_net"]).ljust(16, ' '),
                e["rev_host"] != "<>" and e["rev_host"] or "<{}>".format(e["as_desc"][:30] + (e["as_desc"][30:] and ".."))
            ) for e in data if len(set(suffixes(e["rev_host"])) & set(KNOWN_DNS_SUFF)) > 0 and e["asn"] in KNOWN_GOOD_ASNS])

        old_asn = Counter(
            ["{} {} {}".format(
                e["asn"].ljust(10, ' '),
                e["as_desc"],
                (e["asn"] in AS_COMMENTS.keys() and AS_COMMENTS[e["asn"]] or "")
            ) for e in data if e["asn"] in KNOWN_GOOD_ASNS])

        print("\nStatistics")
        print(" {} unique ASNs, {} unknown, {} known".format(len(new_asn.keys()) + len(old_asn.keys()), len(new_asn.keys()),
                                                             len(old_asn.keys())))
        print(" {} unique IPs, {} unknown, {} known".format(len(new_ips.keys()) + len(old_ips.keys()), len(new_ips.keys()),
                                                            len(old_ips.keys())))

        def print_counter_list(ctr: Counter):
            if len(ctr.keys()) < 1:
                print("empty list")
                return
            most = ctr.most_common(1)[0][1]
            digits = len(str(most))
            print(" " + "\n ".join(["{} {}".format(str(e[1]).rjust(digits, ' '), e[0]) for e in ctr.most_common()]))

        print("\nUnknown ASNs")
        print_counter_list(new_asn)

        print("\nUnknown IPs and Hosts")
        print_counter_list(new_ips)

        print("\nKnown ASNs")
        print_counter_list(old_asn)

        print("\nKnown IPs and Hosts")
        print_counter_list(old_ips)


if __name__ == "__main__":
    main(sys.argv)
