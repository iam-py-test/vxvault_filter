rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "31/03/2023"
   strings:
   		$url1 = "http://ji.jhia6gy44dd.com/m/ss47.exe" ascii wide
		$url2 = "http://79.137.203.144/white.exe" ascii wide
		$url3 = "https://cdn.discordapp.com/attachments/1072409919527067670/1085902945905811507/fleint.exe" ascii wide
		$url4 = "https://insellerate.net/doc/taskshostw.exe" ascii wide
		$url5 = "http://95.214.55.109/bins/zwx86_64" ascii wide
		$url6 = "http://77.73.134.35/bebra.exe" ascii wide
		$url7 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url8 = "http://208.67.105.179/robinzx.exe" ascii wide
		$url9 = "http://46.3.197.29/bins/sora.x86" ascii wide
		$url10 = "https://cdn.discordapp.com/attachments/849373097303080960/1077991259299393606/Cleaner8.exe" ascii wide
		$url11 = "http://185.106.94.190/file1.exe" ascii wide
		$url12 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url13 = "http://80.66.75.36/p-Qfdyajl.exe" ascii wide
		$url14 = "http://80.66.75.36/a-Yfgvvxyduvu.exe" ascii wide
		$url15 = "http://ji.jhia6gyygcc.com/m/ss27.exe" ascii wide
		$url16 = "http://www.cpasdrole.com/handdiy6/handdiy_6.exe" ascii wide
		$url17 = "https://tornomoita.com/RoMunITrLKUraN4728294.exe" ascii wide
		$url18 = "https://a.dowgmua.com/gamexyz/3002/random.exe" ascii wide
		$url19 = "https://www.imagn.world/storage/sqlcmd.exe" ascii wide
		$url20 = "http://15.204.49.145/files/New1.exe" ascii wide
		$url21 = "http://15.204.49.145/files/JavHa.exe" ascii wide
		$url22 = "http://15.204.49.145/files/HAD.exe" ascii wide
		$url23 = "https://transfer.sh/get/t5y8BV/ChatGPT.exe" ascii wide
		$url24 = "http://194.87.35.101/nigga.exe" ascii wide
		$url25 = "https://tap-taptap.com/1488/106.exe" ascii wide
		$url26 = "https://oof00.com/666/105.exe" ascii wide
		$url27 = "https://oof00.com/666/106.exe" ascii wide
		$url28 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url29 = "http://uaery.top/dl/build2.exe" ascii wide
		$url30 = "http://zexeq.com/files/1/build3.exe" ascii wide
		$url31 = "https://eboka.vip/stream.exe" ascii wide
		$url32 = "https://cdn.discordapp.com/attachments/483916447823822851/1079722023502217216/EasyCrypterSupport.exe" ascii wide
		$url33 = "https://cdn.discordapp.com/attachments/1066774563054157866/1067847877860270181/Ace.exe" ascii wide
		$url34 = "http://77.73.134.35/bebra.exe" ascii wide
		$url35 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url36 = "https://bitbucket.org/thisisaworkspace/bumogak/raw/cf339d8869a4980f17da4d2a7ca92d4cd8dfa47b/LK2.exe" ascii wide
		$url37 = "https://bitbucket.org/thisisaworkspace/bumogak/raw/cf339d8869a4980f17da4d2a7ca92d4cd8dfa47b/LEMON.exe" ascii wide
		$url38 = "https://bitbucket.org/thisisaworkspace/bumogak/raw/cf339d8869a4980f17da4d2a7ca92d4cd8dfa47b/DEV.exe" ascii wide
		$url39 = "https://bitbucket.org/thisisaworkspace/bumogak/raw/cf339d8869a4980f17da4d2a7ca92d4cd8dfa47b/DCKA.exe" ascii wide
		$url40 = "https://bbc-s.news/12333.exe" ascii wide
		$url41 = "http://a0782451.xsph.ru/vr/st/Reb.exe" ascii wide
		$url42 = "http://94.142.138.116/dashboard/installer.exe" ascii wide
		$url43 = "http://94.142.138.116/dashboard/pay/new.exe.exe" ascii wide
		$url44 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url45 = "http://193.233.20.19/mi/sonto.exe" ascii wide
		$url46 = "https://github.com/Crysiz2631/sup/raw/main/Software_Requirements.exe" ascii wide
		$url47 = "http://uaery.top/dl/build2.exe" ascii wide
		$url48 = "http://jiqaz.com/files/1/build3.exe" ascii wide
		$url49 = "https://www.franceconsobanque.fr/wp-admin/images/css/design/fabric/bo/Uqvfulhohfm.bmp" ascii wide
		$url50 = "https://gitlab.com/oxx980/1234/-/raw/main/buildnew.exe" ascii wide
		$url51 = "https://merafm.com/wp-content/uploads/2021/02/paf/Talking-Points-with-China-PLAAF.exe" ascii wide
		$url52 = "http://hugersi.com/dl/6523.exe" ascii wide
		$url53 = "http://79.137.207.113/1.exe" ascii wide
		$url54 = "http://193.38.55.218/1.exe" ascii wide
		$url55 = "http://195.74.86.227/five.exe" ascii wide
		$url56 = "http://163.123.143.4/download/Service_soft.bmp" ascii wide
		$url57 = "http://194.110.203.101/puta/brazilx86.exe" ascii wide
		$url58 = "http://hugersi.com/dl/6523.exe" ascii wide
		$url59 = "http://privacy-tools-for-you-453.com/downloads/lab.exe" ascii wide
		$url60 = "http://62.204.41.176/putingod.exe" ascii wide
		$url61 = "http://67.198.237.222/k20/k20sh4" ascii wide
		$url62 = "http://67.198.237.222/k20/k20x86" ascii wide
		$url63 = "http://panel984257.site/Baasbq.dat" ascii wide
		$url64 = "https://dl.dropboxusercontent.com/s/c1hzli34bo5kxwg/update.exe?dl=0" ascii wide
		$url65 = "http://84.21.172.35/polish.exe" ascii wide
		$url66 = "http://185.17.0.54/wvVRGaJtNlPK.exe" ascii wide
		$url67 = "http://167.235.69.31/nppshell.exe" ascii wide
		$url68 = "http://195.201.23.180/urapwd2x.dll" ascii wide
		$url69 = "http://farmriterural.com.au/javonet2.1.exe" ascii wide
		$url70 = "https://cryptoidea.help/downloads/video.exe" ascii wide
		$url71 = "http://cryptoidea.help/downloads/metamask.exe" ascii wide
		$url72 = "https://cdn.discordapp.com/attachments/1052616590480380017/1052617391454040144/autorun.exe" ascii wide
		$url73 = "http://107.189.5.161/Loader.exe" ascii wide
		$url74 = "http://s3rrrv3r.xyz/lll.exe" ascii wide
		$url75 = "https://qtvotqx-krf-6.ml/chibk/Jrxqkbvdpcg.png" ascii wide
		$url76 = "https://qtvotqx-krf-6.ml/olu/Vutbwiazl.bmp" ascii wide
		$url77 = "https://uploadkon.ir/uploads/280e09_22no.rar" ascii wide
		$url78 = "http://h167159.srv11.test-hf.su/53.exe" ascii wide
		$url79 = "http://h167159.srv11.test-hf.su/52.exe" ascii wide
		$url80 = "http://144.168.243.177/113/vbc.exe" ascii wide
		$url81 = "http://103.133.214.139/2/NINJA.exe" ascii wide
		$url82 = "https://unionbindinqcompany.it/vbs.exe" ascii wide
		$url83 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url84 = "http://72.251.235.155/rt/dp/2" ascii wide
		$url85 = "http://72.251.235.155/rt/dp/1" ascii wide
		$url86 = "http://137.175.17.190/mogu/xmg.x86" ascii wide
		$url87 = "http://137.175.17.190/mogu/xmg.arm" ascii wide
		$url88 = "http://77.73.134.24/Clip2.exe" ascii wide
		$url89 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url90 = "http://grantable-excesses.000webhostapp.com/WindowsServices.exe" ascii wide
		$url91 = "http://45.15.159.230/avicapn32.exe" ascii wide
		$url92 = "http://h166794.srv12.test-hf.su/42.exe" ascii wide
		$url93 = "https://orderedami.com/svcrun.exe" ascii wide
		$url94 = "https://nazarene-fire.000webhostapp.com/lio.png" ascii wide
		$url95 = "http://188.93.233.99/n8exrcvvse1m2/avicapn32.exe" ascii wide
		$url96 = "http://179.43.142.79/hapuh/client.exe" ascii wide
		$url97 = "http://37.77.239.239:8752/crypted/Pr0xyWifeStealer.exe" ascii wide
		$url98 = "http://37.77.239.239:8752/crypted/ransom.EXE" ascii wide
		$url99 = "http://37.77.239.239:8752/crypted/nVidiaControllSetup.exe" ascii wide
		$url100 = "http://37.77.239.239:8752/crypted/server5.EXE" ascii wide
		$url101 = "http://37.77.239.239:8752/crypted/stealer.EXE" ascii wide

   condition:
        any of them
}
