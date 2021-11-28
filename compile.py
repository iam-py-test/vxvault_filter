import requests
from urllib.parse import urlparse
from hashlib import sha256
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = """! Title: VXVault filter
! Description: VXVault's latest links compiled into a uBlock Origin compatible filter
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
"""
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
               sha256 += sha256(requests.get(line).content).hexdigest()
            except:
                pass
    else:
        if line != "" and "<pre>" not in line:
            ubolist += "! " + line + "\n"
endfile = open("ubolist.txt","w")
endfile.write(ubolist)
endfile.close()
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
