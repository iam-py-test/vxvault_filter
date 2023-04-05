import re, json, socket, datetime
from urllib.parse import urlparse
from hashlib import sha256

import requests

# static 
LIST_URL = "http://vxvault.net/URL_List.php"
HOMEPAGE_URL = "https://github.com/iam-py-test/vxvault_filter"
SCRIPT_LAST_UPDATED = "4/4/2023" # change when script updated
ALLOWLIST_FILE_NAME = "domains_allowlist.txt"
CREDIT_LINE = f"Data from {LIST_URL}. All credit to VXVault for finding these URLs"
DOMAINS_DESC = f"A filterlist made up of the domains used to host the 100 most recent URLs listed on VXVault, with known safe domains filtered out. All credit to VXVault for finding the original urls"

# global vars
current_date = datetime.date.today().strftime("%d/%m/%Y")

try:
    ulist = requests.get(LIST_URL)
except Exception as err:
    print(f"Unable to fetch URL list from {LIST_URL} due to error: {err}")
    sys.exit(1)

ubolist = f"""! Title: VXVault filterlist (unofficial)
! Description: VXVault's latest 100 links compiled into a filterlist. All credit to VXVault for finding these urls
! Script last updated: {SCRIPT_LAST_UPDATED}
! Expires: 1 day
! Last updated: {current_date}
! Homepage: {HOMEPAGE_URL}
! {CREDIT_LINE}
"""
domains = f"""! Title: VXVault domains (unofficial)
! Description: {DOMAINS_DESC}
! Script last updated: {SCRIPT_LAST_UPDATED}
! Expires: 1 day
! Last updated: {current_date}
! Homepage: {HOMEPAGE_URL}
! {CREDIT_LINE}
"""
HOSTs_header = f"""# VXVault domains (unofficial)
# {DOMAINS_DESC}
# Homepage: {HOMEPAGE_URL}
# Last updated: {current_date}
# {CREDIT_LINE}
"""
LONG_LIVED_HEADER = f"""! Title: VXVault domains longlived (unofficial)
! Expires: 1 day
! Homepage: {HOMEPAGE_URL}
! Last updated: {current_date}
! {CREDIT_LINE}
"""

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
    all_urls_ever = f"""! Title: VXVault filterlist (unofficial)
! Expires: 1 day
! Homepage: {HOMEPAGE_URL}
! {CREDIT_LINE}
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
lines = ulist.text.split("\r\n")
for line in lines:
    if line.startswith("http"):
        all_u.append(line)
        queryparam = ""
        parsedurl = urlparse(line)
        if parsedurl.query != "":
            queryparam = "?" + parsedurl.query
        ubolist += "||" + parsedurl.hostname +  parsedurl.path + queryparam + "^$all\n"
        if "||" + parsedurl.hostname +  parsedurl.path + queryparam + "^$all" not in all_urls_ever:
            all_urls_ever += "||" + parsedurl.hostname +  parsedurl.path + queryparam + "^$all\n"
        if "||" + parsedurl.hostname +  parsedurl.path + queryparam not in fdata and fdata != "":
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

safedomains = open(ALLOWLIST_FILE_NAME, encoding="UTF-8").read().split("\n")
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
  if seendomains[domain]["alive"] == True and domain not in safedomains:
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
""".format(current_date, yara_urls).replace("[ob]","{").replace("[cb]","}")
outyara = open("rule.yar","w", encoding="UTF-8")
outyara.write(yara_rule)
outyara.close()

outdomaininfo = open("seendomains.json",'w', encoding="UTF-8")
outdomaininfo.write(json.dumps(seendomains))
outdomaininfo.close()

