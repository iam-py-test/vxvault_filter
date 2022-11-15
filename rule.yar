rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
        updated = "15/11/2022"
   strings:
   		$url1 = "http://89.208.104.172/412.exe"
		$url2 = "http://89.208.104.172/bebra.exe"
		$url3 = "https://gvcaeorx.tk/tt/palmicc.txt"
		$url4 = "http://208.67.105.179/haitianzx.exe"
		$url5 = "https://github.com/Cteklooo/u/raw/main/free_donate.exe"
		$url6 = "http://istanbulyazilim.net/fh28fu490fiu42.kdfd"
		$url7 = "http://istanbulyazilim.net/1255321213.yutoiop"
		$url8 = "https://cdn.discordapp.com/attachments/1034566764819918851/1040422829100892231/GameLauncher.exe"
		$url9 = "https://cdn.discordapp.com/attachments/963158858975559760/998699040013307994/Final4942080.exe"
		$url10 = "http://cdn.discordapp.com/attachments/1037798440857505884/1037798662920732682/dmi17n.exe"
		$url11 = "https://ezisc.com/dmi1dfg7n.iujgy"
		$url12 = "http://istanbulyazilim.net/ofg7dfg312.wretg"
		$url13 = "http://istanbulyazilim.net/f429f4uf84u.f2hf9842"
		$url14 = "http://istanbulyazilim.net/dmi1dfg7n.iujgy"
		$url15 = "http://uaery.top/dl/build2.exe"
		$url16 = "http://fresherlights.com/files/1/build3.exe"
		$url17 = "http://uaery.top/dl/build2.exe"
		$url18 = "https://bitbucket.org/wres1/new777/downloads/NOTWAR.exe"
		$url19 = "https://bitbucket.org/wres1/new777/downloads/Check.exe"
		$url20 = "http://178.62.211.84/B3O0M3O8H4I2P1/4567585376312434683574.exe"
		$url21 = "http://jhtmuw1v.beget.tech/build/M.exe"
		$url22 = "http://jhtmuw1v.beget.tech/build/H.exe"
		$url23 = "http://89.208.104.172/bebra.exe"
		$url24 = "http://jhtmuw1v.beget.tech/build/A.exe"
		$url25 = "http://89.208.104.172/412.exe"
		$url26 = "http://jhtmuw1v.beget.tech/build/3.exe"
		$url27 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg32.jp"
		$url28 = "http://guluiiiimnstrannaer.net/dl/6523.exe"
		$url29 = "http://uaery.top/dl/buildz.exe"
		$url30 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg2.jp"
		$url31 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/TjerJeTnHj.jk"
		$url32 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ro5io8xv.rt"
		$url33 = "https://mamamiya137.ru/Smart.exe"
		$url34 = "https://cdn.discordapp.com/attachments/1025831078235209788/1034202014403543072/123.exe"
		$url35 = "http://gitcdn.link/cdn/dima11113fg/erty/main/ofg2.jp"
		$url36 = "http://gitcdn.link/cdn/prostoprosto/sdgdfsg/main/ofg.jp"
		$url37 = "https://cdn.discordapp.com/attachments/988460078250205185/1034211170766311485/HyperproviderCommon228.exe"
		$url38 = "http://cghfdyj.b-cdn.net/brave32.exe"
		$url39 = "http://sarlmagsub.com/16/data64_1.exe"
		$url40 = "http://185.223.93.133/conhost.exe"
		$url41 = "http://23.88.123.223/Browser.exe"
		$url42 = "https://mamamiya137.ru/mine/ChomiumPath.exe"
		$url43 = "http://45.83.123.158/admin/avicap32.exe"
		$url44 = "http://217.114.43.68/e85de4a9-bb09-4f45-84a0-d79dc48bc7fa.exe"
		$url45 = "http://103.145.253.70/clouddisk/vbc.exe"
		$url46 = "http://45.139.105.159/files/UyyLYKV.exe"
		$url47 = "http://45.139.105.159/files/FiNfBDd.exe"
		$url48 = "http://198.23.187.168/210/vbc.exe"
		$url49 = "http://111.90.151.174:7777/5200.exe"
		$url50 = "http://111.90.151.174:7777/Ransomworm.exe"
		$url51 = "http://111.90.151.174:7777/Ransomware.exe"
		$url52 = "http://111.90.151.174:7777/5201.exe"
		$url53 = "https://cdn.discordapp.com/attachments/1028313498264023060/1029817776338116628/21N6t.exe"
		$url54 = "https://bitcoinpass.ru/whit/windll32.exe"
		$url55 = "https://bitcoinpass.ru/slf/windll32.exe"
		$url56 = "http://77.73.133.31/v0.9_rebranding_64.exe"
		$url57 = "http://gtok.axfree.com/xxr.exe"
		$url58 = "https://one.liteshare.co/download.php?id=EMM466Y"
		$url59 = "http://huntingknives.shop/crc/tyrird.exe"
		$url60 = "http://193.31.116.239/crypt/public/Update_Downloads/DLL.exe"
		$url61 = "http://45.83.122.242/css/nlauncher.exe"
		$url62 = "http://45.83.122.242/css/avicap32.exe"
		$url63 = "http://45.83.122.242/css/wevtutil.exe"
		$url64 = "http://147.182.192.85/blackyellow.exe"
		$url65 = "http://147.182.192.85/common.exe"
		$url66 = "http://85.192.63.81/ZRkLaxArOkhz.exe"
		$url67 = "http://cleaning.homesecuritypc.com/packages/Jaetbm_Sxzaaqvv.bmp"
		$url68 = "http://79.110.62.23/madeit_Bevuknwa.png"
		$url69 = "http://185.147.34.178/20.png"
		$url70 = "https://bontiakhotel.net/article/Client.exe"
		$url71 = "http://45.155.165.63/tq/loader/uploads/Product_Details_018_RFQ.exe"
		$url72 = "http://194.38.23.170/loader/uploads/new.exe"
		$url73 = "https://bontiakhotel.net/article/Vpeswawqko.exe"
		$url74 = "http://185.17.0.86/bluuuu.exe"
		$url75 = "http://104.222.188.59/put.exe"
		$url76 = "http://185.17.0.86/clipcrypt.exe"
		$url77 = "http://185.17.0.86/mine1cry.exe"
		$url78 = "http://185.17.0.86/stelcrypt.exe"
		$url79 = "http://51.161.11.58/aa.exe"
		$url80 = "http://185.17.0.86/Dt0B1tdnixZl.exe"
		$url81 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url82 = "http://185.17.0.86/blucy.exe"
		$url83 = "http://194.38.23.170/loader/uploads/new.exe"
		$url84 = "http://178.20.45.52/pes.exe"
		$url85 = "http://178.20.45.52/sec/pes.exe"
		$url86 = "http://216.250.251.106/32/vbc.exe"
		$url87 = "http://194.38.23.170/loader/uploads/new.exe"
		$url88 = "https://manomav.com/12/TrdngAnr6339.exe"
		$url89 = "https://manomav.com/12/TrdngAnlzr9949.exe"
		$url90 = "https://manomav.com/12/TrdngAnlzr479932.exe"
		$url91 = "https://manomav.com/12/TrdngAnlzr479112.exe"
		$url92 = "https://manomav.com/12/TrdngAnlzr472032.exe"
		$url93 = "http://84.38.130.219/233/vbc.exe"
		$url94 = "http://194.38.23.170/loader/uploads/new.exe"
		$url95 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url96 = "http://192.3.136.187/288/vbc.exe"
		$url97 = "http://194.38.23.170/loader/uploads/new.exe"
		$url98 = "http://194.38.23.170/loader/uploads/new.exe"
		$url99 = "http://88.198.98.203/277/vbc.exe"
		$url100 = "http://194.38.23.170/new.exe"
		$url101 = "http://itomail.ug/cc.exe"

   condition:
        any of them
}
