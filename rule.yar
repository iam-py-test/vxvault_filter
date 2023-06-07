rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "07/06/2023"
   strings:
   		$url1 = "http://109.205.213.7/bins/UnHAnaAW.x86" ascii wide
		$url2 = "http://192.210.215.42/860/cache_cleaner.exe" ascii wide
		$url3 = "http://koiniosportsde.com/bRzNAmYd/ddsc.exe" ascii wide
		$url4 = "http://79.137.195.246/client12/enc.exe" ascii wide
		$url5 = "http://79.137.195.246/client13/enc.exe" ascii wide
		$url6 = "https://raw.githubusercontent.com/xegefi/XOXO/main/WindowsDefender.exe" ascii wide
		$url7 = "https://cdn.discordapp.com/attachments/1053354068959051837/1113107209493155840/update.exe" ascii wide
		$url8 = "https://raw.githubusercontent.com/duantienty/client/main/kyovn.jpg" ascii wide
		$url9 = "https://raw.githubusercontent.com/duantienty/client/main/Client2.jpg" ascii wide
		$url10 = "http://ji.jahhaega2qq.com/m/p0aw25.exe" ascii wide
		$url11 = "http://ji.ase6gasdegkk.com/m/ss49.exe" ascii wide
		$url12 = "http://94.142.138.148/clp6.exe" ascii wide
		$url13 = "http://94.142.138.116/bebra.exe" ascii wide
		$url14 = "http://h169056.srv22.test-hf.su/135.exe" ascii wide
		$url15 = "http://akrostools.com/baz_uniq.exe" ascii wide
		$url16 = "http://37.220.87.61/Clip1.exe" ascii wide
		$url17 = "http://85.217.144.143/files/123.exe" ascii wide
		$url18 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url19 = "http://80.240.20.250/4D321" ascii wide
		$url20 = "http://link.storjshare.io/jwgxwvintmbhhyz6izi7pm6fk3ga/na5la%2Fkanao%2Fpoweroff.exe?download=1" ascii wide
		$url21 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url22 = "http://85.217.144.143/files/WSearch136Estcott.exe" ascii wide
		$url23 = "http://85.217.144.143/files/123.exe" ascii wide
		$url24 = "https://smartphoodapp.com/miner.exe" ascii wide
		$url25 = "https://rqnsomware.s3.us-east-2.amazonaws.com/malwr.exe" ascii wide
		$url26 = "http://85.217.144.143/files/Lyla131.exe" ascii wide
		$url27 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url28 = "http://85.217.144.143/files/5_6232986114823555269.exe" ascii wide
		$url29 = "http://85.217.144.143/files/123.exe" ascii wide
		$url30 = "https://cdn.discordapp.com/attachments/573050178412740619/644916837238439955/google_gift_card_generator.exe" ascii wide
		$url31 = "http://zenithgurukul.in/v1.exe" ascii wide
		$url32 = "http://85.217.144.143/files/HDCR.exe" ascii wide
		$url33 = "http://85.217.144.143/files/123.exe" ascii wide
		$url34 = "http://85.217.144.143/files/123.exe" ascii wide
		$url35 = "https://snippet.host/rpprwi/raw" ascii wide
		$url36 = "http://85.217.144.143/files/123.exe" ascii wide
		$url37 = "https://maths271.000webhostapp.com/mmm.exe" ascii wide
		$url38 = "http://85.217.144.143/files/123.exe" ascii wide
		$url39 = "http://85.217.144.143/files/123.exe" ascii wide
		$url40 = "https://fakethedead.com/sethlocker.exe" ascii wide
		$url41 = "http://85.217.144.143/files/123.exe" ascii wide
		$url42 = "http://85.217.144.143/files/FL2.exe" ascii wide
		$url43 = "http://85.217.144.143/files/akhrygshdfhdfjgs.c.exe" ascii wide
		$url44 = "https://x0.at/wEjB.exe" ascii wide
		$url45 = "https://beautifulqueen.com.br/Documentos.jpg" ascii wide
		$url46 = "http://d2.okshop168.top/xxx/15/15.ocx" ascii wide
		$url47 = "https://cdn.discordapp.com/attachments/1096076829531574352/1096076987812036759/svchost.exe" ascii wide
		$url48 = "https://cdn.discordapp.com/attachments/1096076829531574352/1097477404122939422/XWorm.exe" ascii wide
		$url49 = "http://103.189.202.201/0000213/vbc.exe" ascii wide
		$url50 = "http://85.217.144.143/files/123.exe" ascii wide
		$url51 = "http://85.217.144.143/files/haddd.exe" ascii wide
		$url52 = "https://famileai.com/php/upsoft/zov.txt" ascii wide
		$url53 = "https://famileai.com/php/upsoft/milmonjey.txt" ascii wide
		$url54 = "https://cdn.discordapp.com/attachments/1098002440479064067/1098002456824270959/YeniLib.dll" ascii wide
		$url55 = "https://files.catbox.moe/xfcdu9.dll" ascii wide
		$url56 = "http://ji.ghwiwwff.com/m/oskg25" ascii wide
		$url57 = "http://140.99.221.199/w01.exe" ascii wide
		$url58 = "http://www.ddtools.top/handdiy6/handdiy_6.exe" ascii wide
		$url59 = "https://www.tobimar.ro/tmp/index.php" ascii wide
		$url60 = "http://140.99.221.199/001.exe" ascii wide
		$url61 = "http://asalroshani.ir/user/uni.exe" ascii wide
		$url62 = "http://65.21.3.192/msiexp.exe" ascii wide
		$url63 = "http://45.15.159.42/XSS1.exe" ascii wide
		$url64 = "https://intercross.shop/index/kXFpZBb.exe" ascii wide
		$url65 = "https://bitbucket.org/dushanbepromo/kingsoft/downloads/OriginalBuild.exe" ascii wide
		$url66 = "https://bitbucket.org/dushanbepromo/kingsoft/downloads/tmpF82D.tmp.exe" ascii wide
		$url67 = "http://simplmizer.duckdns.org/GamingBooster.exe" ascii wide
		$url68 = "https://filebin.net/al5dqiowja8bpmov/explorer.exe" ascii wide
		$url69 = "http://103.170.255.139/B191206/vbc.exe" ascii wide
		$url70 = "http://ji.jhia6gy44dd.com/m/ss47.exe" ascii wide
		$url71 = "http://79.137.203.144/white.exe" ascii wide
		$url72 = "https://cdn.discordapp.com/attachments/1072409919527067670/1085902945905811507/fleint.exe" ascii wide
		$url73 = "https://insellerate.net/doc/taskshostw.exe" ascii wide
		$url74 = "http://95.214.55.109/bins/zwx86_64" ascii wide
		$url75 = "http://77.73.134.35/bebra.exe" ascii wide
		$url76 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url77 = "http://208.67.105.179/robinzx.exe" ascii wide
		$url78 = "http://46.3.197.29/bins/sora.x86" ascii wide
		$url79 = "https://cdn.discordapp.com/attachments/849373097303080960/1077991259299393606/Cleaner8.exe" ascii wide
		$url80 = "http://185.106.94.190/file1.exe" ascii wide
		$url81 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url82 = "http://80.66.75.36/p-Qfdyajl.exe" ascii wide
		$url83 = "http://80.66.75.36/a-Yfgvvxyduvu.exe" ascii wide
		$url84 = "http://ji.jhia6gyygcc.com/m/ss27.exe" ascii wide
		$url85 = "http://www.cpasdrole.com/handdiy6/handdiy_6.exe" ascii wide
		$url86 = "https://tornomoita.com/RoMunITrLKUraN4728294.exe" ascii wide
		$url87 = "https://a.dowgmua.com/gamexyz/3002/random.exe" ascii wide
		$url88 = "https://www.imagn.world/storage/sqlcmd.exe" ascii wide
		$url89 = "http://15.204.49.145/files/New1.exe" ascii wide
		$url90 = "http://15.204.49.145/files/JavHa.exe" ascii wide
		$url91 = "http://15.204.49.145/files/HAD.exe" ascii wide
		$url92 = "https://transfer.sh/get/t5y8BV/ChatGPT.exe" ascii wide
		$url93 = "http://194.87.35.101/nigga.exe" ascii wide
		$url94 = "https://tap-taptap.com/1488/106.exe" ascii wide
		$url95 = "https://oof00.com/666/105.exe" ascii wide
		$url96 = "https://oof00.com/666/106.exe" ascii wide
		$url97 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url98 = "http://uaery.top/dl/build2.exe" ascii wide
		$url99 = "http://zexeq.com/files/1/build3.exe" ascii wide
		$url100 = "https://eboka.vip/stream.exe" ascii wide
		$url101 = "https://cdn.discordapp.com/attachments/483916447823822851/1079722023502217216/EasyCrypterSupport.exe" ascii wide

   condition:
        any of them
}
