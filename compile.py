import requests
from urllib.parse import urlparse
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = ""
lines = list.text.split("\n")
for line in lines:
    if line.startswith("http"):
        queryparam = ""
        if urlparse(line).query != "":
            queryparam = "?" + urlparse(line).query
        ubolist += "||" + urlparse(line).hostname +  urlparse(line).pathname + queryparam
    else:
        if line != "":
            ubolist += "! " + line
endfile = open("ubolist.txt","w")
endfile.write(ubolist)
endfile.close()
