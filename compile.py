import requests
import datetime
from urllib.parse import urlparse
from hashlib import sha256
import re, json
import socket

list = requests.get("http://vxvault.net/URL_List.php")
ubolist = """! Title: VXVault filterlist (unofficial)
! Description: VXVault's latest 100 links compiled into a uBlock Origin compatible filter. All credit to VXVault for finding these urls
! Script last updated: 4/4/2023
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/. All credit to them for finding these URLs
""".format(datetime.date.today().strftime("%d/%m/%Y"))
domains = """! Title: VXVault domains (unofficial)
! Description: A filterlist made up of the domains used to host the 100 most recent URLs listed on VXVault, with known safe domains filtered out. All credit to VXVault for finding these urls
! Script last updated: 9/12/2022
! Expires: 1 day
! Last updated: {}
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/. All credit to them for finding these URLs
""".format(datetime.date.today().strftime("%d/%m/%Y"))
HOSTs_header = """# VXVault domains (unofficial)
#  A filterlist made up of the domains used to host the 100 most recent URLs listed on VXVault, with known safe domains filtered out. All credit to VXVault for finding the original urls
# Homepage: https://github.com/iam-py-test/vxvault_filter
# Last updated: {}
# Data from http://vxvault.net/. All credit to them for finding these URLs
""".format(datetime.date.today().strftime("%d/%m/%Y"))
LONG_LIVED_HEADER = """! Title: VXVault domains longlived (unofficial)
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Last updated: {}
! Data from http://vxvault.net/. All credit to them for finding these URLs
""".format(datetime.date.today().strftime("%d/%m/%Y"))

# https://www.geeksforgeeks.org/how-to-validate-an-ip-address-using-regex/
is_ip_v4 = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
is_ip_v6 = "((([0-9a-fA-F]){1,4})\\:){7}"\
             "([0-9a-fA-F]){1,4}"
is_ip_v4_reg = re.compile(is_ip_v4)
is_ip_v6_reg = re.compile(is_ip_v6)

def isalive(domain):
  try:
    return socket.gethostbyname(domain) != None
  except:
    return False

try:
    all_urls_ever = open("ubolist_full.txt", encoding="UTF-8").read()
except:
    all_urls_ever = """! Title: VXVault filterlist (unofficial)
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
"""
try:
  seendomains = json.loads(open("seendomains.json", encoding="UTF-8").read())
except:
  seendomains = {}

sha256s = ""
all_u = []
try:
    done_hashes = open("sha256s.txt", encoding="UTF-8").read().split("\n")
except:
    done_hashes = []
try:
    fdata = open("ubolist.txt", encoding="UTF-8").read()
except:
    fdata = ""
lines = list.text.split("\r\n")
for line in lines:
    if line.startswith("http"):
        all_u.append(line)
        queryparam = ""
        if urlparse(line).query != "":
            queryparam = "?" + urlparse(line).query
        ubolist += "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all\n"
        if "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all" not in all_urls_ever:
            all_urls_ever += "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all\n"
        if "||" + urlparse(line).hostname +  urlparse(line).path + queryparam not in fdata and fdata != "":
            try:
               r = requests.get(line)
               if r.status_code == 404: # if it is 404, then it probably isn't returning malware
                continue
               print("LINE: ",line)
               payhash = sha256(r.content).hexdigest()
               print("HASH: ",payhash)
               if payhash in done_hashes:
                    print("Already recorded")
                    continue
               sha256s += "{}\n".format(payhash)
            except Exception as err:
                print("ERR: ",err)
    else:
        if line != "" and "<pre>" not in line and "</pre>" not in line and line != "! VX Vault last 100 Links":
            ubolist += "! " + line + "\n"
endfile = open("ubolist.txt","w", encoding="UTF-8")
endfile.write(ubolist)
endfile.close()

all_urlsever = open("ubolist_full.txt",'w', encoding="UTF-8")
all_urlsever.write(all_urls_ever)
all_urlsever.close()

safedomains = open("domains_allowlist.txt", encoding="UTF-8").read().split("\n")
donedomains = []
domainsfile = open("domains_file.txt","w", encoding="UTF-8")
domainsfile.write(domains)
hostsfile = open("hosts.txt",'w', encoding="UTF-8")
hostsfile.write(HOSTs_header)
for url in lines:
    try:
        domain = urlparse(url).netloc
        if domain not in safedomains and domain not in donedomains and domain != "" and line != "VX Vault last 100 Links":
            domainsfile.write("||{}^$all\n".format(domain))
            if re.search(is_ip_v4_reg,domain) == None and re.search(is_ip_v6_reg,domain) == None:
                hostsfile.write("0.0.0.0 {}\n".format(domain))
            donedomains.append(domain)
            if domain not in seendomains:
              seendomains[domain] = {}
            seendomains[domain]["alive"] = isalive(domain)
    except:
        pass
domainsfile.close()

longlived = LONG_LIVED_HEADER
for domain in seendomains:
  if seendomains[domain]["alive"] == True:
    longlived += f"||{domain}^$all\n"
longlivedfile = open("longlived.txt",'w', encoding="UTF-8")
longlivedfile.write(longlived)
longlivedfile.close()
  

with open("sha256s.txt","a", encoding="UTF-8") as f:
    try:
        import random
        import requests
        print(lines)
        f.write(sha256s)
    except Exception as err:
        print(err)
    f.close()

yara_urls = ""
num = 1
for u in all_u:
    yara_urls += "\t\t$url{} = \"{}\" ascii wide\n".format(num,u)
    num += 1
yara_rule = """rule VXVault_match
[ob]
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "{}"
   strings:
   {}
   condition:
        any of them
[cb]
""".format(datetime.date.today().strftime("%d/%m/%Y"),yara_urls).replace("[ob]","{").replace("[cb]","}")
outyara = open("rule.yar","w", encoding="UTF-8")
outyara.write(yara_rule)
outyara.close()

outdomaininfo = open("seendomains.json",'w', encoding="UTF-8")
outdomaininfo.write(json.dumps(seendomains))
outdomaininfo.close()

