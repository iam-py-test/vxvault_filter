rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
   strings:
   		$url1 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg2.jp"
		$url2 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/TjerJeTnHj.jk"
		$url3 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ro5io8xv.rt"
		$url4 = "https://mamamiya137.ru/Smart.exe"
		$url5 = "https://cdn.discordapp.com/attachments/1025831078235209788/1034202014403543072/123.exe"
		$url6 = "http://gitcdn.link/cdn/dima11113fg/erty/main/ofg2.jp"
		$url7 = "http://gitcdn.link/cdn/prostoprosto/sdgdfsg/main/ofg.jp"
		$url8 = "https://cdn.discordapp.com/attachments/988460078250205185/1034211170766311485/HyperproviderCommon228.exe"
		$url9 = "http://cghfdyj.b-cdn.net/brave32.exe"
		$url10 = "http://sarlmagsub.com/16/data64_1.exe"
		$url11 = "http://185.223.93.133/conhost.exe"
		$url12 = "http://23.88.123.223/Browser.exe"
		$url13 = "https://mamamiya137.ru/mine/ChomiumPath.exe"
		$url14 = "http://45.83.123.158/admin/avicap32.exe"
		$url15 = "http://217.114.43.68/e85de4a9-bb09-4f45-84a0-d79dc48bc7fa.exe"
		$url16 = "http://103.145.253.70/clouddisk/vbc.exe"
		$url17 = "http://45.139.105.159/files/UyyLYKV.exe"
		$url18 = "http://45.139.105.159/files/FiNfBDd.exe"
		$url19 = "http://198.23.187.168/210/vbc.exe"
		$url20 = "http://111.90.151.174:7777/5200.exe"
		$url21 = "http://111.90.151.174:7777/Ransomworm.exe"
		$url22 = "http://111.90.151.174:7777/Ransomware.exe"
		$url23 = "http://111.90.151.174:7777/5201.exe"
		$url24 = "https://cdn.discordapp.com/attachments/1028313498264023060/1029817776338116628/21N6t.exe"
		$url25 = "https://bitcoinpass.ru/whit/windll32.exe"
		$url26 = "https://bitcoinpass.ru/slf/windll32.exe"
		$url27 = "http://77.73.133.31/v0.9_rebranding_64.exe"
		$url28 = "http://gtok.axfree.com/xxr.exe"
		$url29 = "https://one.liteshare.co/download.php?id=EMM466Y"
		$url30 = "http://huntingknives.shop/crc/tyrird.exe"
		$url31 = "http://193.31.116.239/crypt/public/Update_Downloads/DLL.exe"
		$url32 = "http://45.83.122.242/css/nlauncher.exe"
		$url33 = "http://45.83.122.242/css/avicap32.exe"
		$url34 = "http://45.83.122.242/css/wevtutil.exe"
		$url35 = "http://147.182.192.85/blackyellow.exe"
		$url36 = "http://147.182.192.85/common.exe"
		$url37 = "http://85.192.63.81/ZRkLaxArOkhz.exe"
		$url38 = "http://cleaning.homesecuritypc.com/packages/Jaetbm_Sxzaaqvv.bmp"
		$url39 = "http://79.110.62.23/madeit_Bevuknwa.png"
		$url40 = "http://185.147.34.178/20.png"
		$url41 = "https://bontiakhotel.net/article/Client.exe"
		$url42 = "http://45.155.165.63/tq/loader/uploads/Product_Details_018_RFQ.exe"
		$url43 = "http://194.38.23.170/loader/uploads/new.exe"
		$url44 = "https://bontiakhotel.net/article/Vpeswawqko.exe"
		$url45 = "http://185.17.0.86/bluuuu.exe"
		$url46 = "http://104.222.188.59/put.exe"
		$url47 = "http://185.17.0.86/clipcrypt.exe"
		$url48 = "http://185.17.0.86/mine1cry.exe"
		$url49 = "http://185.17.0.86/stelcrypt.exe"
		$url50 = "http://51.161.11.58/aa.exe"
		$url51 = "http://185.17.0.86/Dt0B1tdnixZl.exe"
		$url52 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url53 = "http://185.17.0.86/blucy.exe"
		$url54 = "http://194.38.23.170/loader/uploads/new.exe"
		$url55 = "http://178.20.45.52/pes.exe"
		$url56 = "http://178.20.45.52/sec/pes.exe"
		$url57 = "http://216.250.251.106/32/vbc.exe"
		$url58 = "http://194.38.23.170/loader/uploads/new.exe"
		$url59 = "https://manomav.com/12/TrdngAnr6339.exe"
		$url60 = "https://manomav.com/12/TrdngAnlzr9949.exe"
		$url61 = "https://manomav.com/12/TrdngAnlzr479932.exe"
		$url62 = "https://manomav.com/12/TrdngAnlzr479112.exe"
		$url63 = "https://manomav.com/12/TrdngAnlzr472032.exe"
		$url64 = "http://84.38.130.219/233/vbc.exe"
		$url65 = "http://194.38.23.170/loader/uploads/new.exe"
		$url66 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url67 = "http://192.3.136.187/288/vbc.exe"
		$url68 = "http://194.38.23.170/loader/uploads/new.exe"
		$url69 = "http://194.38.23.170/loader/uploads/new.exe"
		$url70 = "http://88.198.98.203/277/vbc.exe"
		$url71 = "http://194.38.23.170/new.exe"
		$url72 = "http://itomail.ug/cc.exe"
		$url73 = "http://194.38.23.170/loader/uploads/new.exe"
		$url74 = "https://cdn.discordapp.com/attachments/1002319488340992093/1018244699775049828/kitty-nocompress_1_Jyqhuxph.png"
		$url75 = "http://193.31.116.239/crypt/public/Update_Downloads/rt.jpg"
		$url76 = "http://79.110.62.66/push/git/pushprocess.exe"
		$url77 = "http://84.38.135.157/223/vbc.exe"
		$url78 = "http://85.209.88.29/nbmn.exe"
		$url79 = "http://85.209.88.29/wevtutil.exe"
		$url80 = "http://85.209.88.29/avicap32.exe"
		$url81 = "http://103.114.163.185/431/vbc.exe"
		$url82 = "http://rgyui.top/dl/build.exe"
		$url83 = "http://derioswinf.org/vento/6523.exe"
		$url84 = "http://host-coin-file-17.com/downloads/toolspab3.exe"
		$url85 = "http://5.255.104.227/ad22b/a84eb.exe"
		$url86 = "http://81.161.229.110/xampp/api.txt"
		$url87 = "http://ameis.andalanmutuenergi.com/home/Payment_Details.exe"
		$url88 = "http://172.86.75.33/C3J7N6F6X3P8I0I0M/17819203282122080878.bin"
		$url89 = "http://173.234.155.22/crypted.exe"
		$url90 = "http://h164671.srv11.test-hf.su/174.exe"
		$url91 = "http://my-med.ga/o/Qsgywcm_Gflznlkz.jpg"
		$url92 = "http://109.206.241.81/htdocs/gWRDK.exe"
		$url93 = "http://wiwirdo.ac.ug/rc.exe"
		$url94 = "http://wiwirdo.ac.ug/cc.exe"
		$url95 = "http://wiwirdo.ac.ug/pm.exe"
		$url96 = "http://wiwirdo.ac.ug/azne.exe"
		$url97 = "http://marnersstyler.ug/zxcvb.exe"
		$url98 = "http://marnersstyler.ug/asdfg.exe"
		$url99 = "http://marnersstyler.ug/asdf.EXE"
		$url100 = "http://marnersstyler.ug/zxcv.EXE"
		$url101 = "https://jg.studio/vast.exe"

   condition:
        any of them
}
