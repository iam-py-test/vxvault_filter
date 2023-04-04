# VXVault filterlist (unofficial)

Several filterlists created from VXVault's URL list. All credit to VXVault for the original data. 

### What is VXVault filterlist & why does it exist?

VXVault filterlist takes the [raw list](http://vxvault.net/URL_List.php) of new malware URLs created by VXVault - which cannot be used in blockers (such as uBlock Origin) -  and transforms it into a list compatible with uBlock Origin. All credit goes to vxvault.net for the original list.

### Formats
- [URLs for uBlock Origin/AdGuard](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/ubolist.txt) <br>
This is just the URLs which VXVault currently has in their "raw" list. This does not filter for false positives and will not include older URLs.
- [All URLs in uBo format](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/ubolist_full.txt) <br>
This includes all of the URLs which have been added the VXVault since when this list was created. Thus, this list includes dead URLs and false positives which have been removed upstream. However, this also has the benifit of blocking older URLs which have fallen off the main list (VXVault only includes the latest 100 entries in the raw export). 
- [Domains in uBo format](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/domains_file.txt) <br>
This includes the domains of all the URLs currently listed in VXVault's raw export, with file hosting services and other safe domains excluded*.
- [Domains in a HOSTs file](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/hosts.txt) <br>
Just the format above, but as a HOSTs file and with IPs screened out.
- [YARA rule](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/rule.yar) <br>
Just a YARA rule for finding files containing any of the VXVault URLs. Limited to the current (as of time of generation) URL list.
- [SHA256s of downloaded files](https://raw.githubusercontent.com/iam-py-test/vxvault_filter/main/sha256s.txt) <br>
Just a list of the SHA256s of the content returned by the VXVault URLs. This is not screened, so it may include 404 pages, Cloudflare, and other non-malware things the server decides to return.

\* [Using this allowlist](https://github.com/iam-py-test/vxvault_filter/blob/main/domains_allowlist.txt). I would not put much faith in this allowlist as I add anything which "looks like file hosting and doesn't have hits on VT".
