import requests
from datetime import date
from urllib.parse import urlparse
from hashlib import sha256
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = """! Title: VXVault filter for uBlock Origin (unofficial)
! Description: VXVault's latest links compiled into a uBlock Origin compatible filter
! Script last updated: 12/9/2022
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
""".format(date.today().strftime("%d/%m/%Y"))
domains = """! Title: VXVault domains (unofficial)
! Description: A version of VxVault.net's latest malware urls containing only the domains of the offending urls
! Script last updated: 12/9/2022
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
""".format(date.today().strftime("%d/%m/%Y"))
try:
    all_urls_ever = open("all_urls_ever.txt")
except:
    all_urls_ever = """! Title: VXVault filter for uBlock Origin (unofficial)
! Expires: 1 day
"""

sha256s = ""
try:
    done_hashes = open("sha256s.txt").read().split("\n")
except:
    done_hashes = []
try:
    fdata = open("ubolist.txt").read()
except:
    fdata = ""
lines = list.text.split("\r\n")
for line in lines:
    if line.startswith("http"):
        queryparam = ""
        if urlparse(line).query != "":
            queryparam = "?" + urlparse(line).query
        ubolist += "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all\n"
        if "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all" not in all_urls_ever:
            all_urls_ever += "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all\n"
        if "||" + urlparse(line).hostname +  urlparse(line).path + queryparam not in fdata and fdata != "":
            try:
               print("LINE: ",line)
               payhash = sha256(requests.get(line).content).hexdigest()
               print("HASH: ",payhash)
               if payhash in done_hashes:
                    print("Already recorded")
                    continue
               sha256s += "{}\n".format(payhash)
            except Exception as err:
                print("ERR: ",err)
    else:
        if line != "" and "<pre>" not in line:
            ubolist += "! " + line + "\n"
endfile = open("ubolist.txt","w")
endfile.write(ubolist)
endfile.close()

all_urlsever = open("ubolist_full.txt",'w')
all_urlsever.write(all_urls_ever)
all_urlsever.close()

safedomains = ["google.com","yahoo.com","duckduckgo.com","wikipedia.org","cdn.discordapp.com","discord.com","discordapp.com","raw.githubusercontent.com","lh3.google.com","drive.google.com","mediafire.com","download.com","googleusercontent.com","github.com","gitlab.com","avatars.githubusercontent.com","transfer.sh","download2264.mediafire.com","download2329.mediafire.com","download2340.mediafire.com","bit.ly","tiny.one",'rotf.lol',"onedrive.live.com","www90.zippyshare.com","www34.zippyshare.com","cdn.filesend.jp","pastebin.com","download2273.mediafire.com"]
donedomains = []
domainsfile = open("domains_file.txt","w")
domainsfile.write(domains)
for url in lines:
    try:
        domain = urlparse(url).netloc
        if domain not in safedomains and domain not in donedomains and domain != "" and line != "VX Vault last 100 Links":
            domainsfile.write("||{}^$all\n".format(domain))
            donedomains.append(domain)
    except:
        pass
domainsfile.close()

with open("sha256s.txt","a") as f:
    try:
        import random
        import requests
        print(lines)
        f.write(sha256s)
    except Exception as err:
        print(err)
    f.close()
