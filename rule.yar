rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "09/03/2025"
   strings:
   		$url1 = "http://hybridemails.ae/esign-app.exe" ascii wide
		$url2 = "http://37.44.238.88/l7vmra" ascii wide
		$url3 = "http://37.44.238.88/spim" ascii wide
		$url4 = "http://185.232.205.104/bins/g4za.arm7" ascii wide
		$url5 = "https://github.com/temperloin/piponis/raw/refs/heads/main/plrifjidicfid.exe" ascii wide
		$url6 = "https://github.com/temperloin/piponis/raw/refs/heads/main/jtunuhhrr.exe" ascii wide
		$url7 = "https://github.com/temperloin/piponis/raw/refs/heads/main/jrirkfiweid.exe" ascii wide
		$url8 = "http://filter.trueddns.com:18066/x/encode/ntoskrnl.b64" ascii wide
		$url9 = "https://github.com/BalletsPistol/d9fb74g8db7d8b7db48df7g8db77f4drb7er8db7fd84d7b1gdb47d8b7brt18bcy87gdfb8hfg74h87fh8bf18h7/raw/refs/heads/main/Encryptor.exe" ascii wide
		$url10 = "http://194.37.81.64/Aqua.x86_64" ascii wide
		$url11 = "http://185.81.68.147/Build.exe" ascii wide
		$url12 = "http://185.81.68.147/zx.exe" ascii wide
		$url13 = "http://185.81.68.147/ssg.exe" ascii wide
		$url14 = "http://185.81.68.147/Update.exe" ascii wide
		$url15 = "https://kiltone.top/stelin/Gosjeufon.cpl" ascii wide
		$url16 = "https://dominikatracy.com/audidg.exe" ascii wide
		$url17 = "http://zakazbuketov.kz/audiodf.exe" ascii wide
		$url18 = "http://80.82.65.70/dl?name=mixthree.exe^" ascii wide
		$url19 = "http://176.113.115.37/ScreenUpdateSync.exe" ascii wide
		$url20 = "http://185.81.68.147/gfx.exe" ascii wide
		$url21 = "http://185.81.68.147/ctx.exe" ascii wide
		$url22 = "http://185.81.68.147/AsyncClient.exe" ascii wide
		$url23 = "http://185.81.68.147/fcxcx.exe" ascii wide
		$url24 = "http://185.81.68.147/vvv.exe" ascii wide
		$url25 = "http://185.215.113.16/inc/Dynpvoy.exe" ascii wide
		$url26 = "http://74.50.95.117/files/Pkaffth.exe" ascii wide
		$url27 = "http://74.50.95.117/files/Hkrrl.exe" ascii wide
		$url28 = "http://45.131.135.227/Captcha.exe" ascii wide
		$url29 = "http://185.7.78.88/bot.arm" ascii wide
		$url30 = "https://mapimwp.org/wp-content/images/pic8.jpg" ascii wide
		$url31 = "https://nasa.r2cloudhikepoo2.shop/NHFMUBEFH4C9ARNQC6U9.bin" ascii wide
		$url32 = "http://83.217.208.37/app/upd.exe" ascii wide
		$url33 = "https://durraactive.com.my/wp-content/images/pic11.jpg" ascii wide
		$url34 = "http://66.63.187.231/657/caspol.exe" ascii wide
		$url35 = "http://66.63.187.150/file/build3.exe" ascii wide
		$url36 = "http://66.63.187.150/file/build2.exe" ascii wide
		$url37 = "http://66.63.187.150/file/build.exe" ascii wide
		$url38 = "https://aquafusion.com.co/ngbx/ngown.exe" ascii wide
		$url39 = "http://59.99.215.146:49697/Mozi.m" ascii wide
		$url40 = "https://github.com/clipaCHEAT/chaaa/raw/refs/heads/main/Built.exe" ascii wide
		$url41 = "https://github.com/Abdulah345/pizdaporc/raw/refs/heads/main/XClient.exe" ascii wide
		$url42 = "https://newvideo.link/temp/xnsjjxja.exe" ascii wide
		$url43 = "http://185.215.113.16/off/def.exe" ascii wide
		$url44 = "https://dewatabalirental.com/4.exe" ascii wide
		$url45 = "https://dewatabalirental.com/3.exe" ascii wide
		$url46 = "https://dewatabalirental.com/2.exe" ascii wide
		$url47 = "https://dewatabalirental.com/1.exe" ascii wide
		$url48 = "https://samzafood.com.my/wp-content/images/pic5.jpg" ascii wide
		$url49 = "https://samzafood.com.my/wp-content/images/pic6.jpg" ascii wide
		$url50 = "https://bitwelly.design/2.exe" ascii wide
		$url51 = "https://bitwelly.design/1.exe" ascii wide
		$url52 = "http://assets.padmamuseum.gov.bd/css/7d26acda3d7c.exe" ascii wide
		$url53 = "http://72.5.42.222:8568/api/dll/zetta" ascii wide
		$url54 = "https://files.catbox.moe/rutcsx.dhj" ascii wide
		$url55 = "http://185.215.113.103/steam/random.exe" ascii wide
		$url56 = "http://185.215.113.103/test/num.exe" ascii wide
		$url57 = "http://185.215.113.103/luma/random.exe" ascii wide
		$url58 = "http://176.113.115.95/thebig/swf.exe" ascii wide
		$url59 = "http://cache.ussc.org/css/67065a0933c9e_UUESUpdater.exe" ascii wide
		$url60 = "http://proxy.siteterbaru.xyz/css/0a839761915d.exe" ascii wide
		$url61 = "http://91.228.10.22/hb/docii.exe" ascii wide
		$url62 = "http://103.130.147.211/Files/22.exe" ascii wide
		$url63 = "http://194.116.215.195/12dsvc.exe" ascii wide
		$url64 = "https://raw.githubusercontent.com/unknwon1352/qawfdasfaw/main/Software.exe" ascii wide
		$url65 = "http://185.215.113.103/mine/random.exe" ascii wide
		$url66 = "http://103.130.147.211/Files/2.exe" ascii wide
		$url67 = "http://147.45.44.104/malesa/66ed86be077bb_12.exe" ascii wide
		$url68 = "http://185.215.113.26/Nework.exe" ascii wide
		$url69 = "http://194.116.215.195/12dsvc.exe" ascii wide
		$url70 = "http://185.215.113.117/inc/LummaC222222.exe" ascii wide
		$url71 = "http://185.215.113.117/inc/crypted.exe" ascii wide
		$url72 = "http://185.215.113.117/inc/needmoney.exe" ascii wide
		$url73 = "http://185.215.113.117/inc/gold.exe" ascii wide
		$url74 = "http://185.215.113.100/steam/random.exe" ascii wide
		$url75 = "https://stolc-download.tech/download/file/stolc_app.exe" ascii wide
		$url76 = "http://twizt.net/lk.exe" ascii wide
		$url77 = "http://ddl.safone.dev/3808735/US+ONLY1.exe?hash=AgADkx" ascii wide
		$url78 = "https://raw.githubusercontent.com/Marcin2123/actualka/main/113133.exe" ascii wide
		$url79 = "http://45.66.231.16/xd_/cyber-x86" ascii wide
		$url80 = "http://91.92.242.124/bins/bin.mips" ascii wide
		$url81 = "http://91.92.246.18/upl/t2.exe" ascii wide
		$url82 = "http://91.92.246.18/upl/t1.exe" ascii wide
		$url83 = "http://45.66.231.213/x86" ascii wide
		$url84 = "http://45.66.231.148/ppc" ascii wide
		$url85 = "http://45.66.231.148/arm7" ascii wide
		$url86 = "http://45.66.231.148/arc" ascii wide
		$url87 = "http://45.66.231.148/x86" ascii wide
		$url88 = "http://27.147.132.114:38521/.i" ascii wide
		$url89 = "http://200.122.211.138:31644/.i" ascii wide
		$url90 = "http://194.42.207.3/se.exe" ascii wide
		$url91 = "http://198.23.165.253/shindex86" ascii wide
		$url92 = "https://b46.oss-cn-hongkong.aliyuncs.com/config/qNVQKFyM.exe" ascii wide
		$url93 = "http://77.91.77.82/lend/ama.exe" ascii wide
		$url94 = "http://77.91.77.82/lend/deep.exe" ascii wide
		$url95 = "http://45.148.10.78/x86" ascii wide
		$url96 = "https://penisware.com/r77/Install.exe" ascii wide
		$url97 = "https://penisware.com/venom/penisware2.exe" ascii wide
		$url98 = "https://penisware.com/xworm/sdchost.exe" ascii wide
		$url99 = "https://penisware.com/venom/scchost.exe" ascii wide
		$url100 = "http://o7labs.top/visual/blob.exe" ascii wide
		$url101 = "http://o7labs.top/visual/bin.exe" ascii wide

   condition:
        any of them
}
