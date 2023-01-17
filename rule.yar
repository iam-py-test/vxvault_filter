rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
        updated = "17/01/2023"
   strings:
   		$url1 = "http://grantable-excesses.000webhostapp.com/WindowsServices.exe"
		$url2 = "http://45.15.159.230/avicapn32.exe"
		$url3 = "http://h166794.srv12.test-hf.su/42.exe"
		$url4 = "https://orderedami.com/svcrun.exe"
		$url5 = "https://nazarene-fire.000webhostapp.com/lio.png"
		$url6 = "http://188.93.233.99/n8exrcvvse1m2/avicapn32.exe"
		$url7 = "http://179.43.142.79/hapuh/client.exe"
		$url8 = "http://37.77.239.239:8752/crypted/Pr0xyWifeStealer.exe"
		$url9 = "http://37.77.239.239:8752/crypted/ransom.EXE"
		$url10 = "http://37.77.239.239:8752/crypted/nVidiaControllSetup.exe"
		$url11 = "http://37.77.239.239:8752/crypted/server5.EXE"
		$url12 = "http://37.77.239.239:8752/crypted/stealer.EXE"
		$url13 = "https://adobetmcdn.net/healthmanagement.exe"
		$url14 = "https://cdn.discordapp.com/attachments/489454962405802007/495984558177517568/system.exe"
		$url15 = "http://89.208.104.172/Amadey_.exe"
		$url16 = "http://77.73.134.24/Clip1.exe"
		$url17 = "http://89.208.104.172/bebra.exe"
		$url18 = "https://divmainbot.pages.dev/xxb.exe"
		$url19 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/limalt.exe"
		$url20 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/devalt.exe"
		$url21 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMSt.exe"
		$url22 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMMin.exe"
		$url23 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DEVMin.exe"
		$url24 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/CLEP.exe"
		$url25 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DevSt.exe"
		$url26 = "http://80.76.51.212/files/adsme.exe"
		$url27 = "http://35.235.126.33/cia.windows.arm.exe"
		$url28 = "http://35.235.126.33/cia.windows.amd64.exe"
		$url29 = "http://35.235.126.33/cia.linux.amd64"
		$url30 = "http://35.235.126.33/cia.windows.386.exe"
		$url31 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/iF3JduUnN5dx.exe"
		$url32 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell32.exe"
		$url33 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell.exe"
		$url34 = "http://ripple-wells-2022.net/n8exrcvvse1m2/syncfiles.dll"
		$url35 = "http://ripple-wells-2022.net/n8exrcvvse1m2/Emit64.exe"
		$url36 = "http://ripple-wells-2022.net/n8exrcvvse1m2/avicapn32.exe"
		$url37 = "http://juggenbande.site/bmbdeathrow/whoismoke/MemoryLoader.exe"
		$url38 = "http://juggenbande.site/bmbdeathrow/whoismoke/Filthy.exe"
		$url39 = "http://91.213.50.36/files/spacemen.exe"
		$url40 = "http://77.73.133.113/lego/barebones1.exe"
		$url41 = "http://mrfreeman.shop/DgxuGixWrsAdtx/wevtutil.exe"
		$url42 = "http://jonnyomar.xyz/nppshell32.exe"
		$url43 = "http://jonnyomar.xyz/nppshell.exe"
		$url44 = "http://198.23.188.139/220/vbc.exe"
		$url45 = "http://techhint24.com/new/Chrome.exe"
		$url46 = "http://198.23.188.139/220/vbc.exe"
		$url47 = "http://198.23.188.139/190/vbc.exe"
		$url48 = "http://198.23.188.139/160/vbc.exe"
		$url49 = "http://198.23.188.139/180/vbc.exe"
		$url50 = "http://192.3.101.26/30/vbc.exe"
		$url51 = "http://77.73.133.113/lego/okok.exe"
		$url52 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp3.exe"
		$url53 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp2.exe"
		$url54 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp1.exe"
		$url55 = "http://info123info.site/clip1.exe"
		$url56 = "https://cdn.discordapp.com/attachments/1013922792204415100/1029136565533933638/Setup.exe"
		$url57 = "http://194.180.48.203/Dspvxt.jpeg"
		$url58 = "http://uaery.top/dl/build2.exe"
		$url59 = "http://guluiiiimnstrannaer.net/dl/6523.exe"
		$url60 = "http://privacy-tools-for-you-453.com/downloads/toolspab4.exe"
		$url61 = "http://uaery.top/dl/buildz.exe"
		$url62 = "http://cnom.sante.gov.ml/core"
		$url63 = "http://cnom.sante.gov.ml/12"
		$url64 = "http://31.42.177.59/wevtutil.exe"
		$url65 = "http://31.42.177.59/kurwa.exe"
		$url66 = "http://85.208.136.89/Explorer/vbc.exe"
		$url67 = "http://89.208.104.172/412.exe"
		$url68 = "http://89.208.104.172/bebra.exe"
		$url69 = "https://gvcaeorx.tk/tt/palmicc.txt"
		$url70 = "http://208.67.105.179/haitianzx.exe"
		$url71 = "https://github.com/Cteklooo/u/raw/main/free_donate.exe"
		$url72 = "http://istanbulyazilim.net/fh28fu490fiu42.kdfd"
		$url73 = "http://istanbulyazilim.net/1255321213.yutoiop"
		$url74 = "https://cdn.discordapp.com/attachments/1034566764819918851/1040422829100892231/GameLauncher.exe"
		$url75 = "https://cdn.discordapp.com/attachments/963158858975559760/998699040013307994/Final4942080.exe"
		$url76 = "http://cdn.discordapp.com/attachments/1037798440857505884/1037798662920732682/dmi17n.exe"
		$url77 = "https://ezisc.com/dmi1dfg7n.iujgy"
		$url78 = "http://istanbulyazilim.net/ofg7dfg312.wretg"
		$url79 = "http://istanbulyazilim.net/f429f4uf84u.f2hf9842"
		$url80 = "http://istanbulyazilim.net/dmi1dfg7n.iujgy"
		$url81 = "http://uaery.top/dl/build2.exe"
		$url82 = "http://fresherlights.com/files/1/build3.exe"
		$url83 = "http://uaery.top/dl/build2.exe"
		$url84 = "https://bitbucket.org/wres1/new777/downloads/NOTWAR.exe"
		$url85 = "https://bitbucket.org/wres1/new777/downloads/Check.exe"
		$url86 = "http://178.62.211.84/B3O0M3O8H4I2P1/4567585376312434683574.exe"
		$url87 = "http://jhtmuw1v.beget.tech/build/M.exe"
		$url88 = "http://jhtmuw1v.beget.tech/build/H.exe"
		$url89 = "http://89.208.104.172/bebra.exe"
		$url90 = "http://jhtmuw1v.beget.tech/build/A.exe"
		$url91 = "http://89.208.104.172/412.exe"
		$url92 = "http://jhtmuw1v.beget.tech/build/3.exe"
		$url93 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg32.jp"
		$url94 = "http://guluiiiimnstrannaer.net/dl/6523.exe"
		$url95 = "http://uaery.top/dl/buildz.exe"
		$url96 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg2.jp"
		$url97 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/TjerJeTnHj.jk"
		$url98 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ro5io8xv.rt"
		$url99 = "https://mamamiya137.ru/Smart.exe"
		$url100 = "https://cdn.discordapp.com/attachments/1025831078235209788/1034202014403543072/123.exe"
		$url101 = "http://gitcdn.link/cdn/dima11113fg/erty/main/ofg2.jp"

   condition:
        any of them
}
