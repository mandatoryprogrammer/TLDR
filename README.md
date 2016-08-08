# TLDR - A Historical TLD Records Archive
This repository is updated every two hours with the results from [DNS zone transfer attempts](https://en.wikipedia.org/wiki/DNS_zone_transfer) against the [root nameservers](https://en.wikipedia.org/wiki/Root_name_server) and all existing TLD servers. This is done to keep record of zone files for various TLDs and to monitor how these zones change overtime.

# View Changes in TLD DNS Data
[Click here to view the list of commits and see how the various TLD zones change overtime.](https://github.com/mandatoryprogrammer/TLDR/commits/master).

# Zone Transfers for Roots and TLDs
Allowing global zone transfers is sometimes considered a security vulnerability due to this functionality giving attackers the ability to easily enumerate all DNS zone data for a specific domain. This is often seen as an issue for system administrators which want to make enumeration of sub-domains and other DNS data hard for malicious actors.

When it comes to TLDs and the root nameservers, zone transfers are shown in a different light. Zone transfers at this level can be benificial as they are an easy way for a TLD to be transparent about its DNS changes. This project is **not** meant to encourage TLD DNS hosting providers to disable global zone transfers but rather to gather data on the ever-changing zone information for the Internet's TLDs.

## Credit
This project was inspired by Peter Bowen's work which can be found here: https://github.com/pzb/TLDs
