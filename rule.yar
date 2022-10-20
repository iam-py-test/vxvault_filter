rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
   strings:
   		$url1 = "http://103.145.253.70/clouddisk/vbc.exe"
		$url2 = "http://45.139.105.159/files/UyyLYKV.exe"
		$url3 = "http://45.139.105.159/files/FiNfBDd.exe"
		$url4 = "http://198.23.187.168/210/vbc.exe"
		$url5 = "http://111.90.151.174:7777/5200.exe"
		$url6 = "http://111.90.151.174:7777/Ransomworm.exe"
		$url7 = "http://111.90.151.174:7777/Ransomware.exe"
		$url8 = "http://111.90.151.174:7777/5201.exe"
		$url9 = "https://cdn.discordapp.com/attachments/1028313498264023060/1029817776338116628/21N6t.exe"
		$url10 = "https://bitcoinpass.ru/whit/windll32.exe"
		$url11 = "https://bitcoinpass.ru/slf/windll32.exe"
		$url12 = "http://77.73.133.31/v0.9_rebranding_64.exe"
		$url13 = "http://gtok.axfree.com/xxr.exe"
		$url14 = "https://one.liteshare.co/download.php?id=EMM466Y"
		$url15 = "http://huntingknives.shop/crc/tyrird.exe"
		$url16 = "http://193.31.116.239/crypt/public/Update_Downloads/DLL.exe"
		$url17 = "http://45.83.122.242/css/nlauncher.exe"
		$url18 = "http://45.83.122.242/css/avicap32.exe"
		$url19 = "http://45.83.122.242/css/wevtutil.exe"
		$url20 = "http://147.182.192.85/blackyellow.exe"
		$url21 = "http://147.182.192.85/common.exe"
		$url22 = "http://85.192.63.81/ZRkLaxArOkhz.exe"
		$url23 = "http://cleaning.homesecuritypc.com/packages/Jaetbm_Sxzaaqvv.bmp"
		$url24 = "http://79.110.62.23/madeit_Bevuknwa.png"
		$url25 = "http://185.147.34.178/20.png"
		$url26 = "https://bontiakhotel.net/article/Client.exe"
		$url27 = "http://45.155.165.63/tq/loader/uploads/Product_Details_018_RFQ.exe"
		$url28 = "http://194.38.23.170/loader/uploads/new.exe"
		$url29 = "https://bontiakhotel.net/article/Vpeswawqko.exe"
		$url30 = "http://185.17.0.86/bluuuu.exe"
		$url31 = "http://104.222.188.59/put.exe"
		$url32 = "http://185.17.0.86/clipcrypt.exe"
		$url33 = "http://185.17.0.86/mine1cry.exe"
		$url34 = "http://185.17.0.86/stelcrypt.exe"
		$url35 = "http://51.161.11.58/aa.exe"
		$url36 = "http://185.17.0.86/Dt0B1tdnixZl.exe"
		$url37 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url38 = "http://185.17.0.86/blucy.exe"
		$url39 = "http://194.38.23.170/loader/uploads/new.exe"
		$url40 = "http://178.20.45.52/pes.exe"
		$url41 = "http://178.20.45.52/sec/pes.exe"
		$url42 = "http://216.250.251.106/32/vbc.exe"
		$url43 = "http://194.38.23.170/loader/uploads/new.exe"
		$url44 = "https://manomav.com/12/TrdngAnr6339.exe"
		$url45 = "https://manomav.com/12/TrdngAnlzr9949.exe"
		$url46 = "https://manomav.com/12/TrdngAnlzr479932.exe"
		$url47 = "https://manomav.com/12/TrdngAnlzr479112.exe"
		$url48 = "https://manomav.com/12/TrdngAnlzr472032.exe"
		$url49 = "http://84.38.130.219/233/vbc.exe"
		$url50 = "http://194.38.23.170/loader/uploads/new.exe"
		$url51 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url52 = "http://192.3.136.187/288/vbc.exe"
		$url53 = "http://194.38.23.170/loader/uploads/new.exe"
		$url54 = "http://194.38.23.170/loader/uploads/new.exe"
		$url55 = "http://88.198.98.203/277/vbc.exe"
		$url56 = "http://194.38.23.170/new.exe"
		$url57 = "http://itomail.ug/cc.exe"
		$url58 = "http://194.38.23.170/loader/uploads/new.exe"
		$url59 = "https://cdn.discordapp.com/attachments/1002319488340992093/1018244699775049828/kitty-nocompress_1_Jyqhuxph.png"
		$url60 = "http://193.31.116.239/crypt/public/Update_Downloads/rt.jpg"
		$url61 = "http://79.110.62.66/push/git/pushprocess.exe"
		$url62 = "http://84.38.135.157/223/vbc.exe"
		$url63 = "http://85.209.88.29/nbmn.exe"
		$url64 = "http://85.209.88.29/wevtutil.exe"
		$url65 = "http://85.209.88.29/avicap32.exe"
		$url66 = "http://103.114.163.185/431/vbc.exe"
		$url67 = "http://rgyui.top/dl/build.exe"
		$url68 = "http://derioswinf.org/vento/6523.exe"
		$url69 = "http://host-coin-file-17.com/downloads/toolspab3.exe"
		$url70 = "http://5.255.104.227/ad22b/a84eb.exe"
		$url71 = "http://81.161.229.110/xampp/api.txt"
		$url72 = "http://ameis.andalanmutuenergi.com/home/Payment_Details.exe"
		$url73 = "http://172.86.75.33/C3J7N6F6X3P8I0I0M/17819203282122080878.bin"
		$url74 = "http://173.234.155.22/crypted.exe"
		$url75 = "http://h164671.srv11.test-hf.su/174.exe"
		$url76 = "http://my-med.ga/o/Qsgywcm_Gflznlkz.jpg"
		$url77 = "http://109.206.241.81/htdocs/gWRDK.exe"
		$url78 = "http://wiwirdo.ac.ug/rc.exe"
		$url79 = "http://wiwirdo.ac.ug/cc.exe"
		$url80 = "http://wiwirdo.ac.ug/pm.exe"
		$url81 = "http://wiwirdo.ac.ug/azne.exe"
		$url82 = "http://marnersstyler.ug/zxcvb.exe"
		$url83 = "http://marnersstyler.ug/asdfg.exe"
		$url84 = "http://marnersstyler.ug/asdf.EXE"
		$url85 = "http://marnersstyler.ug/zxcv.EXE"
		$url86 = "https://jg.studio/vast.exe"
		$url87 = "https://jg.studio/client-build.exe"
		$url88 = "https://jg.studio/c.exe"
		$url89 = "https://jg.studio/8.exe"
		$url90 = "https://jg.studio/1.exe"
		$url91 = "https://jg.studio/00000003.exe"
		$url92 = "http://cleaning.homesecuritypc.com/packages/Gtonboc_Yvfnvcea.bmp"
		$url93 = "http://vitalwbw.beget.tech/forecaster.exe"
		$url94 = "http://208.67.105.125/vik/HENLOAD.txt"
		$url95 = "http://208.67.105.125/vik/henwar.txt"
		$url96 = "http://208.67.105.125/vik/ezzeee.txt"
		$url97 = "http://208.67.105.125/vik/2.txt"
		$url98 = "http://208.67.105.125/vik/ball.txt"
		$url99 = "http://malanche.com/10/data64_5.exe"
		$url100 = "http://malanche.com/15/data64_4.exe"
		$url101 = "http://208.67.105.125/vik/blaq.txt"

   condition:
        any of them
}
