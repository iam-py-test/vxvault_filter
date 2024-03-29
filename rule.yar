rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for URLs listed in VXVault"
        updated = "29/03/2024"
   strings:
   		$url1 = "http://193.233.132.139/silno/download.php" ascii wide
		$url2 = "http://193.233.132.167/retro/random.exe" ascii wide
		$url3 = "http://petalschanging.shop/current.exe" ascii wide
		$url4 = "http://185.149.146.227/bd2.exe" ascii wide
		$url5 = "http://185.172.128.65/syncUpd.exe" ascii wide
		$url6 = "http://sdfjhuz.com/dl/build2.exe" ascii wide
		$url7 = "http://changingpetals.shop/current.exe" ascii wide
		$url8 = "http://193.233.132.139/silno/download.php" ascii wide
		$url9 = "http://185.172.128.6/timeSync.exe" ascii wide
		$url10 = "http://ngovpn.com/share/index.php" ascii wide
		$url11 = "http://5.42.66.22/retail.php" ascii wide
		$url12 = "http://5.42.66.22/space.php" ascii wide
		$url13 = "http://5.42.66.22/getimage.php" ascii wide
		$url14 = "http://195.20.16.46/download/123p.exe" ascii wide
		$url15 = "http://act.fishoaks.net/data/pdf/june.exe" ascii wide
		$url16 = "http://193.233.132.175/server/ww12/AppGate2103v01.exe" ascii wide
		$url17 = "http://193.233.132.139/silno/download.php" ascii wide
		$url18 = "http://185.172.128.65/Ledger-Live.exe" ascii wide
		$url19 = "http://185.172.128.6/timeSync.exe" ascii wide
		$url20 = "http://whyvickyischeater.com/amaa.exe" ascii wide
		$url21 = "http://5.42.66.22/getimage.php" ascii wide
		$url22 = "https://github.com/Gretmeet/nbc938sdu42/raw/main/test.exe" ascii wide
		$url23 = "https://github.com/incoper887/tua/raw/main/Build.exe" ascii wide
		$url24 = "http://5.42.66.22/getimage.php" ascii wide
		$url25 = "http://sajdfue.com/files/1/build3.exe" ascii wide
		$url26 = "http://galandskiyher5.com/downloads/toolspub1.exe" ascii wide
		$url27 = "http://185.172.128.65/Ledger-Live.exe" ascii wide
		$url28 = "http://privacytools-trade.com/downloads/toolspub1.exe" ascii wide
		$url29 = "http://193.233.132.167/cost/ohara.exe" ascii wide
		$url30 = "http://193.233.132.167/cost/random.exe" ascii wide
		$url31 = "http://193.233.132.62:57893/hera/amadka.exe" ascii wide
		$url32 = "http://193.233.132.167/cost/lenin.exe" ascii wide
		$url33 = "https://deft-sunflower-97c3b5.netlify.app/Client-built.exe" ascii wide
		$url34 = "https://fonqqa0rfoutqructznfzudsrdhgeqxeuptevarkgnd.000webhostapp.com/decrypt.exe" ascii wide
		$url35 = "https://nacionalveiculos.com/Software.exe" ascii wide
		$url36 = "http://193.56.255.218/T1403F/audiodg.exe" ascii wide
		$url37 = "http://185.172.128.187/timeSync.exe" ascii wide
		$url38 = "http://185.172.128.187/syncUpd.exe" ascii wide
		$url39 = "http://medfioytrkdkcodlskeej.net/987123.exe" ascii wide
		$url40 = "http://193.233.132.62:57893/hera/amadka.exe" ascii wide
		$url41 = "http://193.233.132.167/cost/lenin.exe" ascii wide
		$url42 = "http://193.233.132.197/crypted.exe" ascii wide
		$url43 = "https://bitbucket.org/bredil555exe/mix1/downloads/mene.exe" ascii wide
		$url44 = "https://sportessentia.home.pl/temp/crypted.exe" ascii wide
		$url45 = "https://nessotechbd.com/TEMPradius.exe" ascii wide
		$url46 = "http://193.233.132.167/cost/ladas.exe" ascii wide
		$url47 = "http://193.233.132.62:57893/hera/amadka.exe" ascii wide
		$url48 = "http://193.233.132.139:30468/zigma/fraer.exe" ascii wide
		$url49 = "http://185.172.128.187/Ledger-Live.exe" ascii wide
		$url50 = "http://185.172.128.187/syncUpd.exe" ascii wide
		$url51 = "http://185.172.128.126/InstallSetupNew.exe" ascii wide
		$url52 = "http://91.92.250.216/page/c11zx.scr" ascii wide
		$url53 = "https://bitbucket.org/j-upsps/microsoft_network1/downloads/a01.exe" ascii wide
		$url54 = "https://bitbucket.org/j-upsps/microsoft_network1/downloads/a03.exe" ascii wide
		$url55 = "https://seastyle.org/7725eaa6592c80f8124e769b4e8a07f7.exe" ascii wide
		$url56 = "http://147.45.47.93:30487/zigma/kefir.exe" ascii wide
		$url57 = "http://185.172.128.187/timeSync.exe" ascii wide
		$url58 = "https://medfioytrkdkcodlskeej.net/987123.exe" ascii wide
		$url59 = "https://bitbucket.org/tanij75843/anij758u3443/downloads/Soft.exe" ascii wide
		$url60 = "https://triedchicken.net/cad54ba5b01423b1af8ec10ab5719d97.exe" ascii wide
		$url61 = "http://195.20.16.46/download/123p.exe" ascii wide
		$url62 = "http://147.45.47.116:8081/static/brg.exe" ascii wide
		$url63 = "http://193.233.132.167/cost/ladas.exe" ascii wide
		$url64 = "http://193.233.132.167/mine/plaza.exe" ascii wide
		$url65 = "http://193.233.132.62:57893/hera/amadka.exe" ascii wide
		$url66 = "http://185.172.128.187/timeSync.exe" ascii wide
		$url67 = "http://185.172.128.187/syncUpd.exe" ascii wide
		$url68 = "http://94.156.8.244/mips" ascii wide
		$url69 = "https://github.com/junlionserto/dfgdbfgndbdsfbhry/raw/main/momsstiflersdgjboigfnbio.exe" ascii wide
		$url70 = "https://github.com/junlionserto/dfbhdfioughfdsiu/raw/main/poolsdnkjfdbndklsnfgb.exe" ascii wide
		$url71 = "https://licocojambamarketplace.com/fwefwe324234234rgeffwehtrwyrhtrhtqwfqwd31443wefefwwfer3232fewwefwefwefqgrqwtherergqefwefqweqfwqf32fefwsda/uploads/lum" ascii wide
		$url72 = "https://licocojambamarketplace.com/fwefwe324234234rgeffwehtrwyrhtrhtqwfqwd31443wefefwwfer3232fewwefwefwefqgrqwtherergqefwefqweqfwqf32fefwsda/uploads/stlc" ascii wide
		$url73 = "https://transfer.sh/get/UbbsCiHlCm/xapaktep_design_crypted_LAB.exe" ascii wide
		$url74 = "http://medfioytrkdkcodlskeej.net/987123.exe" ascii wide
		$url75 = "http://93.123.39.166/s-h.4-.Sakura" ascii wide
		$url76 = "http://195.20.16.46/download/RetailerRise.exe" ascii wide
		$url77 = "http://41.216.183.27/bins/yakuza.arm" ascii wide
		$url78 = "http://91.92.240.69/beastmode/b3astmode.arm" ascii wide
		$url79 = "http://185.215.113.46/cost/fu.exe" ascii wide
		$url80 = "http://185.172.128.127/syncUpd.exe" ascii wide
		$url81 = "http://185.215.113.46/cost/ladas.exe" ascii wide
		$url82 = "http://185.215.113.46/mine/amert.exe" ascii wide
		$url83 = "http://185.215.113.46/mine/plaza.exe" ascii wide
		$url84 = "http://185.172.128.109/InstallSetup3.exe" ascii wide
		$url85 = "http://185.215.113.46/cost/niks.exe" ascii wide
		$url86 = "https://github.com/Sobaka212/n/releases/download/rr/DCRatBuild.exe" ascii wide
		$url87 = "https://github.com/Sobaka212/n/releases/download/rr/ce0b953269c74bc.exe" ascii wide
		$url88 = "http://mahta-netwotk.click/111.exe" ascii wide
		$url89 = "http://clean.sunaviat.com/data/pdf/june.exe" ascii wide
		$url90 = "http://185.172.128.127/timeSync.exe" ascii wide
		$url91 = "http://brusuax.com/dl/build2.exe" ascii wide
		$url92 = "http://185.172.128.154/hv.exe" ascii wide
		$url93 = "http://185.172.128.19/dayroc.exe" ascii wide
		$url94 = "http://185.172.128.32/sc.exe" ascii wide
		$url95 = "https://45.13.227.186/bins/sora.mips" ascii wide
		$url96 = "http://195.20.16.46/download/RetailerRise.exe" ascii wide
		$url97 = "http://185.172.128.154/hv.exe" ascii wide
		$url98 = "http://ji.alie3ksggg.com/ef/rty45.exe" ascii wide
		$url99 = "http://mix.avalmag.com/data/pdf/june.exe" ascii wide
		$url100 = "http://109.107.182.38/retro/dota.exe" ascii wide
		$url101 = "http://185.172.128.127/timeSync.exe" ascii wide

   condition:
        any of them
}
