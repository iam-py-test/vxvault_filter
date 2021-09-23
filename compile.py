import requests
from urllib.parse import urlparse
list = requests.get("http://vxvault.net/URL_List.php")
ubolist = ""
lines = list.text.split("\n")
for line in lines:
    if line.startswith("http"):
      ubolist += urlparse(line)
