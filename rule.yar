rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "22/06/2024"
   strings:
   		$url1 = "http://77.91.77.82/lend/deep.exe" ascii wide
		$url2 = "http://45.148.10.78/x86" ascii wide
		$url3 = "https://penisware.com/r77/Install.exe" ascii wide
		$url4 = "https://penisware.com/venom/penisware2.exe" ascii wide
		$url5 = "https://penisware.com/xworm/sdchost.exe" ascii wide
		$url6 = "https://penisware.com/venom/scchost.exe" ascii wide
		$url7 = "http://o7labs.top/visual/blob.exe" ascii wide
		$url8 = "http://o7labs.top/visual/bin.exe" ascii wide
		$url9 = "http://147.78.103.47/bins/jew.ppc" ascii wide
		$url10 = "http://universalmovies.top/john.scr" ascii wide
		$url11 = "http://147.78.103.184/sparc" ascii wide
		$url12 = "http://93.123.39.110/softbot.x86" ascii wide
		$url13 = "http://204.137.14.135/s2.exe" ascii wide
		$url14 = "http://147.78.103.195/ws8ioUp8Us" ascii wide
		$url15 = "http://147.78.103.195/ivy5dNMhe9" ascii wide
		$url16 = "http://147.78.103.195/YU5FcDWihk" ascii wide
		$url17 = "http://147.78.103.195/XdYLSM59XW" ascii wide
		$url18 = "http://93.123.39.98/bins/sora.mips" ascii wide
		$url19 = "http://147.78.103.195/gjui" ascii wide
		$url20 = "http://93.123.39.20/bins/r.x86" ascii wide
		$url21 = "http://147.78.103.177/arm6" ascii wide
		$url22 = "http://45.142.182.70/arc" ascii wide
		$url23 = "http://103.228.37.56/most-x86" ascii wide
		$url24 = "http://45.128.232.15/596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.x86" ascii wide
		$url25 = "http://172.105.121.169/AsyncClient.exe" ascii wide
		$url26 = "http://aefieiaehfiaehr.top/tdrpload.exe" ascii wide
		$url27 = "http://5.42.96.55/lumma0805.exe" ascii wide
		$url28 = "https://files.eintim.me/content/cdn/VIShpbWCxEUY.exe" ascii wide
		$url29 = "http://zffsg.oss-ap-northeast-2.aliyuncs.com/x103.log" ascii wide
		$url30 = "http://203.55.81.4/masjesuscan" ascii wide
		$url31 = "https://github.com/Synapsesys/Synapse/releases/download/ah/Discord.exe" ascii wide
		$url32 = "https://raw.githubusercontent.com/musaalif6969/krunker/main/my.exe" ascii wide
		$url33 = "https://github.com/SetThreadExecutionState/ModifiedDiscordClient/raw/main/yar.exe" ascii wide
		$url34 = "http://173.44.139.198/i6" ascii wide
		$url35 = "https://site-nbg.com/Orcamento_HEJOASSUADMINISTRACAO_.PDF6784372024.exe" ascii wide
		$url36 = "https://github.com/ExeXeam/Test/raw/main/Discord.exe" ascii wide
		$url37 = "https://bitbucket.org/silentdown/kadzumi/downloads/Silent.exe" ascii wide
		$url38 = "https://spy-ware-dudu.squareweb.app/donwload" ascii wide
		$url39 = "http://45.88.90.46/bot.arm5" ascii wide
		$url40 = "http://103.14.226.142/x86" ascii wide
		$url41 = "http://185.196.11.177/bins/sora.spc" ascii wide
		$url42 = "http://103.14.226.142/ppc" ascii wide
		$url43 = "http://179.43.190.218/mips" ascii wide
		$url44 = "http://212.70.149.10/i686" ascii wide
		$url45 = "http://twizt.net/shitload.exe" ascii wide
		$url46 = "http://5.42.66.10/download/th/Retailer_prog.exe" ascii wide
		$url47 = "https://jeuxviddeo.com/zyohg9odyvknmq9zlh" ascii wide
		$url48 = "http://45.88.90.30/bot.ppc" ascii wide
		$url49 = "http://putin.zelenskyj.ru/bot.arm" ascii wide
		$url50 = "http://103.113.70.99:7766/version_2.exe" ascii wide
		$url51 = "http://5.181.190.250/cbrbinaries/cbr.arc" ascii wide
		$url52 = "https://kisanbethak.com/JK/ujjdjd.exe" ascii wide
		$url53 = "http://45.129.199.237/df/clip.exe" ascii wide
		$url54 = "https://45.32.18.189/a14407a2" ascii wide
		$url55 = "http://185.215.113.46/sauna/download.php" ascii wide
		$url56 = "http://sly.fishoaks.net/data/pdf/june.exe" ascii wide
		$url57 = "http://5.42.66.10/download/th/retail.php" ascii wide
		$url58 = "http://5.42.66.10/download/th/space.php" ascii wide
		$url59 = "http://5.42.66.10/download/123p.exe" ascii wide
		$url60 = "http://5.42.66.10/download/th/getimage12.php" ascii wide
		$url61 = "http://185.172.128.6/timeSync.exe" ascii wide
		$url62 = "http://193.233.132.175/server/ww12/AppGate2103v01.exe" ascii wide
		$url63 = "https://github.com/Pidoras883/-/releases/download/huesos/IjerkOff.exe" ascii wide
		$url64 = "http://185.172.128.144/ISetup8.exe" ascii wide
		$url65 = "http://185.172.128.144/ISetup10.exe" ascii wide
		$url66 = "http://185.172.128.144/ISetup9.exe" ascii wide
		$url67 = "http://185.172.128.144/ISetup5.exe" ascii wide
		$url68 = "http://185.172.128.144/ISetup1.exe" ascii wide
		$url69 = "http://185.172.128.65/syncUpd.exe" ascii wide
		$url70 = "http://185.172.128.144/ISetup2.exe" ascii wide
		$url71 = "http://193.233.132.139/silno/download.php" ascii wide
		$url72 = "http://193.233.132.167/retro/random.exe" ascii wide
		$url73 = "http://petalschanging.shop/current.exe" ascii wide
		$url74 = "http://185.149.146.227/bd2.exe" ascii wide
		$url75 = "http://185.172.128.65/syncUpd.exe" ascii wide
		$url76 = "http://sdfjhuz.com/dl/build2.exe" ascii wide
		$url77 = "http://changingpetals.shop/current.exe" ascii wide
		$url78 = "http://193.233.132.139/silno/download.php" ascii wide
		$url79 = "http://185.172.128.6/timeSync.exe" ascii wide
		$url80 = "http://ngovpn.com/share/index.php" ascii wide
		$url81 = "http://5.42.66.22/retail.php" ascii wide
		$url82 = "http://5.42.66.22/space.php" ascii wide
		$url83 = "http://5.42.66.22/getimage.php" ascii wide
		$url84 = "http://195.20.16.46/download/123p.exe" ascii wide
		$url85 = "http://act.fishoaks.net/data/pdf/june.exe" ascii wide
		$url86 = "http://193.233.132.175/server/ww12/AppGate2103v01.exe" ascii wide
		$url87 = "http://193.233.132.139/silno/download.php" ascii wide
		$url88 = "http://185.172.128.65/Ledger-Live.exe" ascii wide
		$url89 = "http://185.172.128.6/timeSync.exe" ascii wide
		$url90 = "http://whyvickyischeater.com/amaa.exe" ascii wide
		$url91 = "http://5.42.66.22/getimage.php" ascii wide
		$url92 = "https://github.com/Gretmeet/nbc938sdu42/raw/main/test.exe" ascii wide
		$url93 = "https://github.com/incoper887/tua/raw/main/Build.exe" ascii wide
		$url94 = "http://5.42.66.22/getimage.php" ascii wide
		$url95 = "http://sajdfue.com/files/1/build3.exe" ascii wide
		$url96 = "http://galandskiyher5.com/downloads/toolspub1.exe" ascii wide
		$url97 = "http://185.172.128.65/Ledger-Live.exe" ascii wide
		$url98 = "http://privacytools-trade.com/downloads/toolspub1.exe" ascii wide
		$url99 = "http://193.233.132.167/cost/ohara.exe" ascii wide
		$url100 = "http://193.233.132.167/cost/random.exe" ascii wide
		$url101 = "http://193.233.132.62:57893/hera/amadka.exe" ascii wide

   condition:
        any of them
}
