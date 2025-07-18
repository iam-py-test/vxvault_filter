rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "18/07/2025"
   strings:
   		$url1 = "http://213.209.150.48/arm7" ascii wide
		$url2 = "http://185.39.207.117/ppc" ascii wide
		$url3 = "http://103.175.16.117/mips" ascii wide
		$url4 = "http://31.170.22.205/bins/whisper.x64" ascii wide
		$url5 = "http://196.251.115.212/x86_64" ascii wide
		$url6 = "https://github.com/deripascod/coderoom/raw/refs/heads/main/kythkkaewdth.exe" ascii wide
		$url7 = "https://raw.githubusercontent.com/XeroxzB/weqeq/main/XClient.exe" ascii wide
		$url8 = "http://62.60.226.112/file/590_9883.exe" ascii wide
		$url9 = "https://recursoscompartidos.xyz/pora/csc.exe" ascii wide
		$url10 = "http://176.65.134.5/arm" ascii wide
		$url11 = "http://176.65.134.62/bins/morte.x86" ascii wide
		$url12 = "http://hybridemails.ae/esign-app.exe" ascii wide
		$url13 = "http://37.44.238.88/l7vmra" ascii wide
		$url14 = "http://37.44.238.88/spim" ascii wide
		$url15 = "http://185.232.205.104/bins/g4za.arm7" ascii wide
		$url16 = "https://github.com/temperloin/piponis/raw/refs/heads/main/plrifjidicfid.exe" ascii wide
		$url17 = "https://github.com/temperloin/piponis/raw/refs/heads/main/jtunuhhrr.exe" ascii wide
		$url18 = "https://github.com/temperloin/piponis/raw/refs/heads/main/jrirkfiweid.exe" ascii wide
		$url19 = "http://filter.trueddns.com:18066/x/encode/ntoskrnl.b64" ascii wide
		$url20 = "https://github.com/BalletsPistol/d9fb74g8db7d8b7db48df7g8db77f4drb7er8db7fd84d7b1gdb47d8b7brt18bcy87gdfb8hfg74h87fh8bf18h7/raw/refs/heads/main/Encryptor.exe" ascii wide
		$url21 = "http://194.37.81.64/Aqua.x86_64" ascii wide
		$url22 = "http://185.81.68.147/Build.exe" ascii wide
		$url23 = "http://185.81.68.147/zx.exe" ascii wide
		$url24 = "http://185.81.68.147/ssg.exe" ascii wide
		$url25 = "http://185.81.68.147/Update.exe" ascii wide
		$url26 = "https://kiltone.top/stelin/Gosjeufon.cpl" ascii wide
		$url27 = "https://dominikatracy.com/audidg.exe" ascii wide
		$url28 = "http://zakazbuketov.kz/audiodf.exe" ascii wide
		$url29 = "http://80.82.65.70/dl?name=mixthree.exe^" ascii wide
		$url30 = "http://176.113.115.37/ScreenUpdateSync.exe" ascii wide
		$url31 = "http://185.81.68.147/gfx.exe" ascii wide
		$url32 = "http://185.81.68.147/ctx.exe" ascii wide
		$url33 = "http://185.81.68.147/AsyncClient.exe" ascii wide
		$url34 = "http://185.81.68.147/fcxcx.exe" ascii wide
		$url35 = "http://185.81.68.147/vvv.exe" ascii wide
		$url36 = "http://185.215.113.16/inc/Dynpvoy.exe" ascii wide
		$url37 = "http://74.50.95.117/files/Pkaffth.exe" ascii wide
		$url38 = "http://74.50.95.117/files/Hkrrl.exe" ascii wide
		$url39 = "http://45.131.135.227/Captcha.exe" ascii wide
		$url40 = "http://185.7.78.88/bot.arm" ascii wide
		$url41 = "https://mapimwp.org/wp-content/images/pic8.jpg" ascii wide
		$url42 = "https://nasa.r2cloudhikepoo2.shop/NHFMUBEFH4C9ARNQC6U9.bin" ascii wide
		$url43 = "http://83.217.208.37/app/upd.exe" ascii wide
		$url44 = "https://durraactive.com.my/wp-content/images/pic11.jpg" ascii wide
		$url45 = "http://66.63.187.231/657/caspol.exe" ascii wide
		$url46 = "http://66.63.187.150/file/build3.exe" ascii wide
		$url47 = "http://66.63.187.150/file/build2.exe" ascii wide
		$url48 = "http://66.63.187.150/file/build.exe" ascii wide
		$url49 = "https://aquafusion.com.co/ngbx/ngown.exe" ascii wide
		$url50 = "http://59.99.215.146:49697/Mozi.m" ascii wide
		$url51 = "https://github.com/clipaCHEAT/chaaa/raw/refs/heads/main/Built.exe" ascii wide
		$url52 = "https://github.com/Abdulah345/pizdaporc/raw/refs/heads/main/XClient.exe" ascii wide
		$url53 = "https://newvideo.link/temp/xnsjjxja.exe" ascii wide
		$url54 = "http://185.215.113.16/off/def.exe" ascii wide
		$url55 = "https://dewatabalirental.com/4.exe" ascii wide
		$url56 = "https://dewatabalirental.com/3.exe" ascii wide
		$url57 = "https://dewatabalirental.com/2.exe" ascii wide
		$url58 = "https://dewatabalirental.com/1.exe" ascii wide
		$url59 = "https://samzafood.com.my/wp-content/images/pic5.jpg" ascii wide
		$url60 = "https://samzafood.com.my/wp-content/images/pic6.jpg" ascii wide
		$url61 = "https://bitwelly.design/2.exe" ascii wide
		$url62 = "https://bitwelly.design/1.exe" ascii wide
		$url63 = "http://assets.padmamuseum.gov.bd/css/7d26acda3d7c.exe" ascii wide
		$url64 = "http://72.5.42.222:8568/api/dll/zetta" ascii wide
		$url65 = "https://files.catbox.moe/rutcsx.dhj" ascii wide
		$url66 = "http://185.215.113.103/steam/random.exe" ascii wide
		$url67 = "http://185.215.113.103/test/num.exe" ascii wide
		$url68 = "http://185.215.113.103/luma/random.exe" ascii wide
		$url69 = "http://176.113.115.95/thebig/swf.exe" ascii wide
		$url70 = "http://cache.ussc.org/css/67065a0933c9e_UUESUpdater.exe" ascii wide
		$url71 = "http://proxy.siteterbaru.xyz/css/0a839761915d.exe" ascii wide
		$url72 = "http://91.228.10.22/hb/docii.exe" ascii wide
		$url73 = "http://103.130.147.211/Files/22.exe" ascii wide
		$url74 = "http://194.116.215.195/12dsvc.exe" ascii wide
		$url75 = "https://raw.githubusercontent.com/unknwon1352/qawfdasfaw/main/Software.exe" ascii wide
		$url76 = "http://185.215.113.103/mine/random.exe" ascii wide
		$url77 = "http://103.130.147.211/Files/2.exe" ascii wide
		$url78 = "http://147.45.44.104/malesa/66ed86be077bb_12.exe" ascii wide
		$url79 = "http://185.215.113.26/Nework.exe" ascii wide
		$url80 = "http://194.116.215.195/12dsvc.exe" ascii wide
		$url81 = "http://185.215.113.117/inc/LummaC222222.exe" ascii wide
		$url82 = "http://185.215.113.117/inc/crypted.exe" ascii wide
		$url83 = "http://185.215.113.117/inc/needmoney.exe" ascii wide
		$url84 = "http://185.215.113.117/inc/gold.exe" ascii wide
		$url85 = "http://185.215.113.100/steam/random.exe" ascii wide
		$url86 = "https://stolc-download.tech/download/file/stolc_app.exe" ascii wide
		$url87 = "http://twizt.net/lk.exe" ascii wide
		$url88 = "http://ddl.safone.dev/3808735/US+ONLY1.exe?hash=AgADkx" ascii wide
		$url89 = "https://raw.githubusercontent.com/Marcin2123/actualka/main/113133.exe" ascii wide
		$url90 = "http://45.66.231.16/xd_/cyber-x86" ascii wide
		$url91 = "http://91.92.242.124/bins/bin.mips" ascii wide
		$url92 = "http://91.92.246.18/upl/t2.exe" ascii wide
		$url93 = "http://91.92.246.18/upl/t1.exe" ascii wide
		$url94 = "http://45.66.231.213/x86" ascii wide
		$url95 = "http://45.66.231.148/ppc" ascii wide
		$url96 = "http://45.66.231.148/arm7" ascii wide
		$url97 = "http://45.66.231.148/arc" ascii wide
		$url98 = "http://45.66.231.148/x86" ascii wide
		$url99 = "http://27.147.132.114:38521/.i" ascii wide
		$url100 = "http://200.122.211.138:31644/.i" ascii wide
		$url101 = "http://194.42.207.3/se.exe" ascii wide

   condition:
        any of them
}
