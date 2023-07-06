rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "06/07/2023"
   strings:
   		$url1 = "https://cdn.discordapp.com/attachments/1124469077491069010/1124473530491338752/inteldrv.exe" ascii wide
		$url2 = "http://23.137.249.127/ddw23/pstol1.exe" ascii wide
		$url3 = "http://103.95.196.149/mips" ascii wide
		$url4 = "http://45.66.230.149/offer/updChrome.exe" ascii wide
		$url5 = "http://allansworthng.com/1/data64_2.exe" ascii wide
		$url6 = "https://sofancy.co.za/data/IqXYLXKzl6.exe" ascii wide
		$url7 = "http://192.3.109.146/325/DaHost.exe" ascii wide
		$url8 = "http://161.35.160.195/P9G9T9M9D7P/18715498712833059056.bin" ascii wide
		$url9 = "http://141.98.6.99/Uzlrz.exe" ascii wide
		$url10 = "http://192.3.109.135/24/Dahost.exe" ascii wide
		$url11 = "http://23.94.148.6/GIB.exe" ascii wide
		$url12 = "http://23.94.144.13/555/vbc.exe" ascii wide
		$url13 = "https://bluestaks.novationgroups.com/post/ClipperDoej4oa.exe" ascii wide
		$url14 = "https://bluestaks.novationgroups.com/post/Upshotox64.exe" ascii wide
		$url15 = "https://bluestaks.novationgroups.com/post/p5zl9bq82kjf7.exe" ascii wide
		$url16 = "http://africatechs.com/YoutubeAdvert.exe" ascii wide
		$url17 = "http://miateknik.com/Amday.exe" ascii wide
		$url18 = "http://51.79.49.73/crc/Play.exe" ascii wide
		$url19 = "http://51.79.49.73/crc/bz.exe" ascii wide
		$url20 = "http://134.122.135.4/datelog.dll" ascii wide
		$url21 = "http://distroforex.com/crona.exe" ascii wide
		$url22 = "http://89.185.85.117/laupdate.exe" ascii wide
		$url23 = "http://94.142.138.116/bebra.exe" ascii wide
		$url24 = "https://filebin.net/zexd4wguldbgaetq/rh1.exe" ascii wide
		$url25 = "https://raw.githubusercontent.com/duantienty/client/main/tdc.jpg" ascii wide
		$url26 = "http://file.gta5cheatcode.world/dashboard/file/dxpserver.exe" ascii wide
		$url27 = "http://file.gta5cheatcode.world/dashboard/file/dxpserver.exe" ascii wide
		$url28 = "http://109.205.213.7/bins/UnHAnaAW.x86" ascii wide
		$url29 = "http://192.210.215.42/860/cache_cleaner.exe" ascii wide
		$url30 = "http://koiniosportsde.com/bRzNAmYd/ddsc.exe" ascii wide
		$url31 = "http://79.137.195.246/client12/enc.exe" ascii wide
		$url32 = "http://79.137.195.246/client13/enc.exe" ascii wide
		$url33 = "https://raw.githubusercontent.com/xegefi/XOXO/main/WindowsDefender.exe" ascii wide
		$url34 = "https://cdn.discordapp.com/attachments/1053354068959051837/1113107209493155840/update.exe" ascii wide
		$url35 = "https://raw.githubusercontent.com/duantienty/client/main/kyovn.jpg" ascii wide
		$url36 = "https://raw.githubusercontent.com/duantienty/client/main/Client2.jpg" ascii wide
		$url37 = "http://ji.jahhaega2qq.com/m/p0aw25.exe" ascii wide
		$url38 = "http://ji.ase6gasdegkk.com/m/ss49.exe" ascii wide
		$url39 = "http://94.142.138.148/clp6.exe" ascii wide
		$url40 = "http://94.142.138.116/bebra.exe" ascii wide
		$url41 = "http://h169056.srv22.test-hf.su/135.exe" ascii wide
		$url42 = "http://akrostools.com/baz_uniq.exe" ascii wide
		$url43 = "http://37.220.87.61/Clip1.exe" ascii wide
		$url44 = "http://85.217.144.143/files/123.exe" ascii wide
		$url45 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url46 = "http://80.240.20.250/4D321" ascii wide
		$url47 = "http://link.storjshare.io/jwgxwvintmbhhyz6izi7pm6fk3ga/na5la%2Fkanao%2Fpoweroff.exe?download=1" ascii wide
		$url48 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url49 = "http://85.217.144.143/files/WSearch136Estcott.exe" ascii wide
		$url50 = "http://85.217.144.143/files/123.exe" ascii wide
		$url51 = "https://smartphoodapp.com/miner.exe" ascii wide
		$url52 = "https://rqnsomware.s3.us-east-2.amazonaws.com/malwr.exe" ascii wide
		$url53 = "http://85.217.144.143/files/Lyla131.exe" ascii wide
		$url54 = "http://85.217.144.143/files/Had.exe" ascii wide
		$url55 = "http://85.217.144.143/files/5_6232986114823555269.exe" ascii wide
		$url56 = "http://85.217.144.143/files/123.exe" ascii wide
		$url57 = "https://cdn.discordapp.com/attachments/573050178412740619/644916837238439955/google_gift_card_generator.exe" ascii wide
		$url58 = "http://zenithgurukul.in/v1.exe" ascii wide
		$url59 = "http://85.217.144.143/files/HDCR.exe" ascii wide
		$url60 = "http://85.217.144.143/files/123.exe" ascii wide
		$url61 = "http://85.217.144.143/files/123.exe" ascii wide
		$url62 = "https://snippet.host/rpprwi/raw" ascii wide
		$url63 = "http://85.217.144.143/files/123.exe" ascii wide
		$url64 = "https://maths271.000webhostapp.com/mmm.exe" ascii wide
		$url65 = "http://85.217.144.143/files/123.exe" ascii wide
		$url66 = "http://85.217.144.143/files/123.exe" ascii wide
		$url67 = "https://fakethedead.com/sethlocker.exe" ascii wide
		$url68 = "http://85.217.144.143/files/123.exe" ascii wide
		$url69 = "http://85.217.144.143/files/FL2.exe" ascii wide
		$url70 = "http://85.217.144.143/files/akhrygshdfhdfjgs.c.exe" ascii wide
		$url71 = "https://x0.at/wEjB.exe" ascii wide
		$url72 = "https://beautifulqueen.com.br/Documentos.jpg" ascii wide
		$url73 = "http://d2.okshop168.top/xxx/15/15.ocx" ascii wide
		$url74 = "https://cdn.discordapp.com/attachments/1096076829531574352/1096076987812036759/svchost.exe" ascii wide
		$url75 = "https://cdn.discordapp.com/attachments/1096076829531574352/1097477404122939422/XWorm.exe" ascii wide
		$url76 = "http://103.189.202.201/0000213/vbc.exe" ascii wide
		$url77 = "http://85.217.144.143/files/123.exe" ascii wide
		$url78 = "http://85.217.144.143/files/haddd.exe" ascii wide
		$url79 = "https://famileai.com/php/upsoft/zov.txt" ascii wide
		$url80 = "https://famileai.com/php/upsoft/milmonjey.txt" ascii wide
		$url81 = "https://cdn.discordapp.com/attachments/1098002440479064067/1098002456824270959/YeniLib.dll" ascii wide
		$url82 = "https://files.catbox.moe/xfcdu9.dll" ascii wide
		$url83 = "http://ji.ghwiwwff.com/m/oskg25" ascii wide
		$url84 = "http://140.99.221.199/w01.exe" ascii wide
		$url85 = "http://www.ddtools.top/handdiy6/handdiy_6.exe" ascii wide
		$url86 = "https://www.tobimar.ro/tmp/index.php" ascii wide
		$url87 = "http://140.99.221.199/001.exe" ascii wide
		$url88 = "http://asalroshani.ir/user/uni.exe" ascii wide
		$url89 = "http://65.21.3.192/msiexp.exe" ascii wide
		$url90 = "http://45.15.159.42/XSS1.exe" ascii wide
		$url91 = "https://intercross.shop/index/kXFpZBb.exe" ascii wide
		$url92 = "https://bitbucket.org/dushanbepromo/kingsoft/downloads/OriginalBuild.exe" ascii wide
		$url93 = "https://bitbucket.org/dushanbepromo/kingsoft/downloads/tmpF82D.tmp.exe" ascii wide
		$url94 = "http://simplmizer.duckdns.org/GamingBooster.exe" ascii wide
		$url95 = "https://filebin.net/al5dqiowja8bpmov/explorer.exe" ascii wide
		$url96 = "http://103.170.255.139/B191206/vbc.exe" ascii wide
		$url97 = "http://ji.jhia6gy44dd.com/m/ss47.exe" ascii wide
		$url98 = "http://79.137.203.144/white.exe" ascii wide
		$url99 = "https://cdn.discordapp.com/attachments/1072409919527067670/1085902945905811507/fleint.exe" ascii wide
		$url100 = "https://insellerate.net/doc/taskshostw.exe" ascii wide
		$url101 = "http://95.214.55.109/bins/zwx86_64" ascii wide

   condition:
        any of them
}
