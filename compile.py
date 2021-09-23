import requests
from urllib.parse import urlparse
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = """! Title: VXVault filter
! Description: VXVault's latest links compiled into a uBlock Origin compatible filter
! Expires: 1 day
! Homepage: https://github.com/iam-py-test/vxvault_filter
! Data from http://vxvault.net/
"""
lines = list.text.split("\n")
for line in lines:
    if line.startswith("http"):
        queryparam = ""
        if urlparse(line).query != "":
            queryparam = "?" + urlparse(line).query
        ubolist += "||" + urlparse(line).hostname +  urlparse(line).path + queryparam + "^$all\n"
    else:
        if line != "" and "<pre>" not in line:
            ubolist += "! " + line + "\n"
endfile = open("ubolist.txt","w")
endfile.write(ubolist)
endfile.close()
