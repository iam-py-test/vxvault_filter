rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
        updated = "16/02/2023"
   strings:
   		$url1 = "http://67.198.237.222/k20/k20sh4" ascii wide
		$url2 = "http://67.198.237.222/k20/k20x86" ascii wide
		$url3 = "http://panel984257.site/Baasbq.dat" ascii wide
		$url4 = "https://dl.dropboxusercontent.com/s/c1hzli34bo5kxwg/update.exe?dl=0" ascii wide
		$url5 = "http://84.21.172.35/polish.exe" ascii wide
		$url6 = "http://185.17.0.54/wvVRGaJtNlPK.exe" ascii wide
		$url7 = "http://167.235.69.31/nppshell.exe" ascii wide
		$url8 = "http://195.201.23.180/urapwd2x.dll" ascii wide
		$url9 = "http://farmriterural.com.au/javonet2.1.exe" ascii wide
		$url10 = "https://cryptoidea.help/downloads/video.exe" ascii wide
		$url11 = "http://cryptoidea.help/downloads/metamask.exe" ascii wide
		$url12 = "https://cdn.discordapp.com/attachments/1052616590480380017/1052617391454040144/autorun.exe" ascii wide
		$url13 = "http://107.189.5.161/Loader.exe" ascii wide
		$url14 = "http://s3rrrv3r.xyz/lll.exe" ascii wide
		$url15 = "https://qtvotqx-krf-6.ml/chibk/Jrxqkbvdpcg.png" ascii wide
		$url16 = "https://qtvotqx-krf-6.ml/olu/Vutbwiazl.bmp" ascii wide
		$url17 = "https://uploadkon.ir/uploads/280e09_22no.rar" ascii wide
		$url18 = "http://h167159.srv11.test-hf.su/53.exe" ascii wide
		$url19 = "http://h167159.srv11.test-hf.su/52.exe" ascii wide
		$url20 = "http://144.168.243.177/113/vbc.exe" ascii wide
		$url21 = "http://103.133.214.139/2/NINJA.exe" ascii wide
		$url22 = "https://unionbindinqcompany.it/vbs.exe" ascii wide
		$url23 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url24 = "http://72.251.235.155/rt/dp/2" ascii wide
		$url25 = "http://72.251.235.155/rt/dp/1" ascii wide
		$url26 = "http://137.175.17.190/mogu/xmg.x86" ascii wide
		$url27 = "http://137.175.17.190/mogu/xmg.arm" ascii wide
		$url28 = "http://77.73.134.24/Clip2.exe" ascii wide
		$url29 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url30 = "http://grantable-excesses.000webhostapp.com/WindowsServices.exe" ascii wide
		$url31 = "http://45.15.159.230/avicapn32.exe" ascii wide
		$url32 = "http://h166794.srv12.test-hf.su/42.exe" ascii wide
		$url33 = "https://orderedami.com/svcrun.exe" ascii wide
		$url34 = "https://nazarene-fire.000webhostapp.com/lio.png" ascii wide
		$url35 = "http://188.93.233.99/n8exrcvvse1m2/avicapn32.exe" ascii wide
		$url36 = "http://179.43.142.79/hapuh/client.exe" ascii wide
		$url37 = "http://37.77.239.239:8752/crypted/Pr0xyWifeStealer.exe" ascii wide
		$url38 = "http://37.77.239.239:8752/crypted/ransom.EXE" ascii wide
		$url39 = "http://37.77.239.239:8752/crypted/nVidiaControllSetup.exe" ascii wide
		$url40 = "http://37.77.239.239:8752/crypted/server5.EXE" ascii wide
		$url41 = "http://37.77.239.239:8752/crypted/stealer.EXE" ascii wide
		$url42 = "https://adobetmcdn.net/healthmanagement.exe" ascii wide
		$url43 = "https://cdn.discordapp.com/attachments/489454962405802007/495984558177517568/system.exe" ascii wide
		$url44 = "http://89.208.104.172/Amadey_.exe" ascii wide
		$url45 = "http://77.73.134.24/Clip1.exe" ascii wide
		$url46 = "http://89.208.104.172/bebra.exe" ascii wide
		$url47 = "https://divmainbot.pages.dev/xxb.exe" ascii wide
		$url48 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/limalt.exe" ascii wide
		$url49 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/devalt.exe" ascii wide
		$url50 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMSt.exe" ascii wide
		$url51 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMMin.exe" ascii wide
		$url52 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DEVMin.exe" ascii wide
		$url53 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/CLEP.exe" ascii wide
		$url54 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DevSt.exe" ascii wide
		$url55 = "http://80.76.51.212/files/adsme.exe" ascii wide
		$url56 = "http://35.235.126.33/cia.windows.arm.exe" ascii wide
		$url57 = "http://35.235.126.33/cia.windows.amd64.exe" ascii wide
		$url58 = "http://35.235.126.33/cia.linux.amd64" ascii wide
		$url59 = "http://35.235.126.33/cia.windows.386.exe" ascii wide
		$url60 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/iF3JduUnN5dx.exe" ascii wide
		$url61 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell32.exe" ascii wide
		$url62 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell.exe" ascii wide
		$url63 = "http://ripple-wells-2022.net/n8exrcvvse1m2/syncfiles.dll" ascii wide
		$url64 = "http://ripple-wells-2022.net/n8exrcvvse1m2/Emit64.exe" ascii wide
		$url65 = "http://ripple-wells-2022.net/n8exrcvvse1m2/avicapn32.exe" ascii wide
		$url66 = "http://juggenbande.site/bmbdeathrow/whoismoke/MemoryLoader.exe" ascii wide
		$url67 = "http://juggenbande.site/bmbdeathrow/whoismoke/Filthy.exe" ascii wide
		$url68 = "http://91.213.50.36/files/spacemen.exe" ascii wide
		$url69 = "http://77.73.133.113/lego/barebones1.exe" ascii wide
		$url70 = "http://mrfreeman.shop/DgxuGixWrsAdtx/wevtutil.exe" ascii wide
		$url71 = "http://jonnyomar.xyz/nppshell32.exe" ascii wide
		$url72 = "http://jonnyomar.xyz/nppshell.exe" ascii wide
		$url73 = "http://198.23.188.139/220/vbc.exe" ascii wide
		$url74 = "http://techhint24.com/new/Chrome.exe" ascii wide
		$url75 = "http://198.23.188.139/220/vbc.exe" ascii wide
		$url76 = "http://198.23.188.139/190/vbc.exe" ascii wide
		$url77 = "http://198.23.188.139/160/vbc.exe" ascii wide
		$url78 = "http://198.23.188.139/180/vbc.exe" ascii wide
		$url79 = "http://192.3.101.26/30/vbc.exe" ascii wide
		$url80 = "http://77.73.133.113/lego/okok.exe" ascii wide
		$url81 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp3.exe" ascii wide
		$url82 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp2.exe" ascii wide
		$url83 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp1.exe" ascii wide
		$url84 = "http://info123info.site/clip1.exe" ascii wide
		$url85 = "https://cdn.discordapp.com/attachments/1013922792204415100/1029136565533933638/Setup.exe" ascii wide
		$url86 = "http://194.180.48.203/Dspvxt.jpeg" ascii wide
		$url87 = "http://uaery.top/dl/build2.exe" ascii wide
		$url88 = "http://guluiiiimnstrannaer.net/dl/6523.exe" ascii wide
		$url89 = "http://privacy-tools-for-you-453.com/downloads/toolspab4.exe" ascii wide
		$url90 = "http://uaery.top/dl/buildz.exe" ascii wide
		$url91 = "http://cnom.sante.gov.ml/core" ascii wide
		$url92 = "http://cnom.sante.gov.ml/12" ascii wide
		$url93 = "http://31.42.177.59/wevtutil.exe" ascii wide
		$url94 = "http://31.42.177.59/kurwa.exe" ascii wide
		$url95 = "http://85.208.136.89/Explorer/vbc.exe" ascii wide
		$url96 = "http://89.208.104.172/412.exe" ascii wide
		$url97 = "http://89.208.104.172/bebra.exe" ascii wide
		$url98 = "https://gvcaeorx.tk/tt/palmicc.txt" ascii wide
		$url99 = "http://208.67.105.179/haitianzx.exe" ascii wide
		$url100 = "https://github.com/Cteklooo/u/raw/main/free_donate.exe" ascii wide
		$url101 = "http://istanbulyazilim.net/fh28fu490fiu42.kdfd" ascii wide

   condition:
        any of them
}
