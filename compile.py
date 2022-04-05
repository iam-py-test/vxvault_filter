import requests
from urllib.parse import urlparse
from hashlib import sha256
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = """! Title: VXVault filter
! Description: VXVault's latest links compiled into a uBlock Origin compatible filter
! Script last updated: 4/4/2022
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
""".format(date.today().strftime("%d/%m/%Y"))
domains = """! Title: VXVault domains
! Description: A version of VxVault.net's latest malware urls containing only the domains of the offending urls
! Script last updated: 4/4/2022
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
""".format(date.today().strftime("%d/%m/%Y"))

sha256s = ""
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
        if "||" + urlparse(line).hostname +  urlparse(line).path + queryparam not in fdata and fdata != "":
            try:
               sha256 += sha256(requests.get(line).content).hexdigest() + "\n"
            except:
                pass
    else:
        if line != "" and "<pre>" not in line:
            ubolist += "! " + line + "\n"
endfile = open("ubolist.txt","w")
endfile.write(ubolist)
endfile.close()

safedomains = ["google.com","yahoo.com","duckduckgo.com","wikipedia.org","cdn.discordapp.com","discord.com","discordapp.com","raw.githubusercontent.com","lh3.google.com","drive.google.com","mediafire.com","download.com","googleusercontent.com","github.com","gitlab.com","avatars.githubusercontent.com","transfer.sh","download2264.mediafire.com","download2329.mediafire.com","download2340.mediafire.com","bit.ly"]
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
        f.write(sha256(requests.get(random.choice(lines)).content).hexdigest())
    except Exception as err:
        print(err)
    try:
        import random
        import requests
        print(lines)
        f.write(sha256(requests.get(lines[0]).content).hexdigest())
    except Exception as err:
        print(err)
    f.close()
