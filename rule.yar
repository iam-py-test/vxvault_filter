rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
   strings:
   		$url1 = "http://217.114.43.68/e85de4a9-bb09-4f45-84a0-d79dc48bc7fa.exe"
		$url2 = "http://103.145.253.70/clouddisk/vbc.exe"
		$url3 = "http://45.139.105.159/files/UyyLYKV.exe"
		$url4 = "http://45.139.105.159/files/FiNfBDd.exe"
		$url5 = "http://198.23.187.168/210/vbc.exe"
		$url6 = "http://111.90.151.174:7777/5200.exe"
		$url7 = "http://111.90.151.174:7777/Ransomworm.exe"
		$url8 = "http://111.90.151.174:7777/Ransomware.exe"
		$url9 = "http://111.90.151.174:7777/5201.exe"
		$url10 = "https://cdn.discordapp.com/attachments/1028313498264023060/1029817776338116628/21N6t.exe"
		$url11 = "https://bitcoinpass.ru/whit/windll32.exe"
		$url12 = "https://bitcoinpass.ru/slf/windll32.exe"
		$url13 = "http://77.73.133.31/v0.9_rebranding_64.exe"
		$url14 = "http://gtok.axfree.com/xxr.exe"
		$url15 = "https://one.liteshare.co/download.php?id=EMM466Y"
		$url16 = "http://huntingknives.shop/crc/tyrird.exe"
		$url17 = "http://193.31.116.239/crypt/public/Update_Downloads/DLL.exe"
		$url18 = "http://45.83.122.242/css/nlauncher.exe"
		$url19 = "http://45.83.122.242/css/avicap32.exe"
		$url20 = "http://45.83.122.242/css/wevtutil.exe"
		$url21 = "http://147.182.192.85/blackyellow.exe"
		$url22 = "http://147.182.192.85/common.exe"
		$url23 = "http://85.192.63.81/ZRkLaxArOkhz.exe"
		$url24 = "http://cleaning.homesecuritypc.com/packages/Jaetbm_Sxzaaqvv.bmp"
		$url25 = "http://79.110.62.23/madeit_Bevuknwa.png"
		$url26 = "http://185.147.34.178/20.png"
		$url27 = "https://bontiakhotel.net/article/Client.exe"
		$url28 = "http://45.155.165.63/tq/loader/uploads/Product_Details_018_RFQ.exe"
		$url29 = "http://194.38.23.170/loader/uploads/new.exe"
		$url30 = "https://bontiakhotel.net/article/Vpeswawqko.exe"
		$url31 = "http://185.17.0.86/bluuuu.exe"
		$url32 = "http://104.222.188.59/put.exe"
		$url33 = "http://185.17.0.86/clipcrypt.exe"
		$url34 = "http://185.17.0.86/mine1cry.exe"
		$url35 = "http://185.17.0.86/stelcrypt.exe"
		$url36 = "http://51.161.11.58/aa.exe"
		$url37 = "http://185.17.0.86/Dt0B1tdnixZl.exe"
		$url38 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url39 = "http://185.17.0.86/blucy.exe"
		$url40 = "http://194.38.23.170/loader/uploads/new.exe"
		$url41 = "http://178.20.45.52/pes.exe"
		$url42 = "http://178.20.45.52/sec/pes.exe"
		$url43 = "http://216.250.251.106/32/vbc.exe"
		$url44 = "http://194.38.23.170/loader/uploads/new.exe"
		$url45 = "https://manomav.com/12/TrdngAnr6339.exe"
		$url46 = "https://manomav.com/12/TrdngAnlzr9949.exe"
		$url47 = "https://manomav.com/12/TrdngAnlzr479932.exe"
		$url48 = "https://manomav.com/12/TrdngAnlzr479112.exe"
		$url49 = "https://manomav.com/12/TrdngAnlzr472032.exe"
		$url50 = "http://84.38.130.219/233/vbc.exe"
		$url51 = "http://194.38.23.170/loader/uploads/new.exe"
		$url52 = "http://delicatedownload.co.uk/Geekbench-5.4.5-WindowsSetup.exe"
		$url53 = "http://192.3.136.187/288/vbc.exe"
		$url54 = "http://194.38.23.170/loader/uploads/new.exe"
		$url55 = "http://194.38.23.170/loader/uploads/new.exe"
		$url56 = "http://88.198.98.203/277/vbc.exe"
		$url57 = "http://194.38.23.170/new.exe"
		$url58 = "http://itomail.ug/cc.exe"
		$url59 = "http://194.38.23.170/loader/uploads/new.exe"
		$url60 = "https://cdn.discordapp.com/attachments/1002319488340992093/1018244699775049828/kitty-nocompress_1_Jyqhuxph.png"
		$url61 = "http://193.31.116.239/crypt/public/Update_Downloads/rt.jpg"
		$url62 = "http://79.110.62.66/push/git/pushprocess.exe"
		$url63 = "http://84.38.135.157/223/vbc.exe"
		$url64 = "http://85.209.88.29/nbmn.exe"
		$url65 = "http://85.209.88.29/wevtutil.exe"
		$url66 = "http://85.209.88.29/avicap32.exe"
		$url67 = "http://103.114.163.185/431/vbc.exe"
		$url68 = "http://rgyui.top/dl/build.exe"
		$url69 = "http://derioswinf.org/vento/6523.exe"
		$url70 = "http://host-coin-file-17.com/downloads/toolspab3.exe"
		$url71 = "http://5.255.104.227/ad22b/a84eb.exe"
		$url72 = "http://81.161.229.110/xampp/api.txt"
		$url73 = "http://ameis.andalanmutuenergi.com/home/Payment_Details.exe"
		$url74 = "http://172.86.75.33/C3J7N6F6X3P8I0I0M/17819203282122080878.bin"
		$url75 = "http://173.234.155.22/crypted.exe"
		$url76 = "http://h164671.srv11.test-hf.su/174.exe"
		$url77 = "http://my-med.ga/o/Qsgywcm_Gflznlkz.jpg"
		$url78 = "http://109.206.241.81/htdocs/gWRDK.exe"
		$url79 = "http://wiwirdo.ac.ug/rc.exe"
		$url80 = "http://wiwirdo.ac.ug/cc.exe"
		$url81 = "http://wiwirdo.ac.ug/pm.exe"
		$url82 = "http://wiwirdo.ac.ug/azne.exe"
		$url83 = "http://marnersstyler.ug/zxcvb.exe"
		$url84 = "http://marnersstyler.ug/asdfg.exe"
		$url85 = "http://marnersstyler.ug/asdf.EXE"
		$url86 = "http://marnersstyler.ug/zxcv.EXE"
		$url87 = "https://jg.studio/vast.exe"
		$url88 = "https://jg.studio/client-build.exe"
		$url89 = "https://jg.studio/c.exe"
		$url90 = "https://jg.studio/8.exe"
		$url91 = "https://jg.studio/1.exe"
		$url92 = "https://jg.studio/00000003.exe"
		$url93 = "http://cleaning.homesecuritypc.com/packages/Gtonboc_Yvfnvcea.bmp"
		$url94 = "http://vitalwbw.beget.tech/forecaster.exe"
		$url95 = "http://208.67.105.125/vik/HENLOAD.txt"
		$url96 = "http://208.67.105.125/vik/henwar.txt"
		$url97 = "http://208.67.105.125/vik/ezzeee.txt"
		$url98 = "http://208.67.105.125/vik/2.txt"
		$url99 = "http://208.67.105.125/vik/ball.txt"
		$url100 = "http://malanche.com/10/data64_5.exe"
		$url101 = "http://malanche.com/15/data64_4.exe"

   condition:
        any of them
}