rule VXVault_match
{
   meta:
        author = "iam-py-test"
        description = "Autogenerated YARA rule checking for the VXVault urls"
        updated = "23/12/2022"
   strings:
   		$url1 = "http://37.77.239.239:8752/crypted/Pr0xyWifeStealer.exe"
		$url2 = "http://37.77.239.239:8752/crypted/ransom.EXE"
		$url3 = "http://37.77.239.239:8752/crypted/nVidiaControllSetup.exe"
		$url4 = "http://37.77.239.239:8752/crypted/server5.EXE"
		$url5 = "http://37.77.239.239:8752/crypted/stealer.EXE"
		$url6 = "https://adobetmcdn.net/healthmanagement.exe"
		$url7 = "https://cdn.discordapp.com/attachments/489454962405802007/495984558177517568/system.exe"
		$url8 = "http://89.208.104.172/Amadey_.exe"
		$url9 = "http://77.73.134.24/Clip1.exe"
		$url10 = "http://89.208.104.172/bebra.exe"
		$url11 = "https://divmainbot.pages.dev/xxb.exe"
		$url12 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/limalt.exe"
		$url13 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/devalt.exe"
		$url14 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMSt.exe"
		$url15 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/LIMMin.exe"
		$url16 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DEVMin.exe"
		$url17 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/CLEP.exe"
		$url18 = "https://bitbucket.org/lucifer61156/thisisforeducationalpurposesonly/raw/bc18553af2861543b406b0ca967d1ff48501f86a/DevSt.exe"
		$url19 = "http://80.76.51.212/files/adsme.exe"
		$url20 = "http://35.235.126.33/cia.windows.arm.exe"
		$url21 = "http://35.235.126.33/cia.windows.amd64.exe"
		$url22 = "http://35.235.126.33/cia.linux.amd64"
		$url23 = "http://35.235.126.33/cia.windows.386.exe"
		$url24 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/iF3JduUnN5dx.exe"
		$url25 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell32.exe"
		$url26 = "http://ripple-wells-2022.net/yzoyoebw6fqrey/nppshell.exe"
		$url27 = "http://ripple-wells-2022.net/n8exrcvvse1m2/syncfiles.dll"
		$url28 = "http://ripple-wells-2022.net/n8exrcvvse1m2/Emit64.exe"
		$url29 = "http://ripple-wells-2022.net/n8exrcvvse1m2/avicapn32.exe"
		$url30 = "http://juggenbande.site/bmbdeathrow/whoismoke/MemoryLoader.exe"
		$url31 = "http://juggenbande.site/bmbdeathrow/whoismoke/Filthy.exe"
		$url32 = "http://91.213.50.36/files/spacemen.exe"
		$url33 = "http://77.73.133.113/lego/barebones1.exe"
		$url34 = "http://mrfreeman.shop/DgxuGixWrsAdtx/wevtutil.exe"
		$url35 = "http://jonnyomar.xyz/nppshell32.exe"
		$url36 = "http://jonnyomar.xyz/nppshell.exe"
		$url37 = "http://198.23.188.139/220/vbc.exe"
		$url38 = "http://techhint24.com/new/Chrome.exe"
		$url39 = "http://198.23.188.139/220/vbc.exe"
		$url40 = "http://198.23.188.139/190/vbc.exe"
		$url41 = "http://198.23.188.139/160/vbc.exe"
		$url42 = "http://198.23.188.139/180/vbc.exe"
		$url43 = "http://192.3.101.26/30/vbc.exe"
		$url44 = "http://77.73.133.113/lego/okok.exe"
		$url45 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp3.exe"
		$url46 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp2.exe"
		$url47 = "https://github.com/Chelloxy/Do-not-Try-this-at-Home/raw/main/Temp1.exe"
		$url48 = "http://info123info.site/clip1.exe"
		$url49 = "https://cdn.discordapp.com/attachments/1013922792204415100/1029136565533933638/Setup.exe"
		$url50 = "http://194.180.48.203/Dspvxt.jpeg"
		$url51 = "http://uaery.top/dl/build2.exe"
		$url52 = "http://guluiiiimnstrannaer.net/dl/6523.exe"
		$url53 = "http://privacy-tools-for-you-453.com/downloads/toolspab4.exe"
		$url54 = "http://uaery.top/dl/buildz.exe"
		$url55 = "http://cnom.sante.gov.ml/core"
		$url56 = "http://cnom.sante.gov.ml/12"
		$url57 = "http://31.42.177.59/wevtutil.exe"
		$url58 = "http://31.42.177.59/kurwa.exe"
		$url59 = "http://85.208.136.89/Explorer/vbc.exe"
		$url60 = "http://89.208.104.172/412.exe"
		$url61 = "http://89.208.104.172/bebra.exe"
		$url62 = "https://gvcaeorx.tk/tt/palmicc.txt"
		$url63 = "http://208.67.105.179/haitianzx.exe"
		$url64 = "https://github.com/Cteklooo/u/raw/main/free_donate.exe"
		$url65 = "http://istanbulyazilim.net/fh28fu490fiu42.kdfd"
		$url66 = "http://istanbulyazilim.net/1255321213.yutoiop"
		$url67 = "https://cdn.discordapp.com/attachments/1034566764819918851/1040422829100892231/GameLauncher.exe"
		$url68 = "https://cdn.discordapp.com/attachments/963158858975559760/998699040013307994/Final4942080.exe"
		$url69 = "http://cdn.discordapp.com/attachments/1037798440857505884/1037798662920732682/dmi17n.exe"
		$url70 = "https://ezisc.com/dmi1dfg7n.iujgy"
		$url71 = "http://istanbulyazilim.net/ofg7dfg312.wretg"
		$url72 = "http://istanbulyazilim.net/f429f4uf84u.f2hf9842"
		$url73 = "http://istanbulyazilim.net/dmi1dfg7n.iujgy"
		$url74 = "http://uaery.top/dl/build2.exe"
		$url75 = "http://fresherlights.com/files/1/build3.exe"
		$url76 = "http://uaery.top/dl/build2.exe"
		$url77 = "https://bitbucket.org/wres1/new777/downloads/NOTWAR.exe"
		$url78 = "https://bitbucket.org/wres1/new777/downloads/Check.exe"
		$url79 = "http://178.62.211.84/B3O0M3O8H4I2P1/4567585376312434683574.exe"
		$url80 = "http://jhtmuw1v.beget.tech/build/M.exe"
		$url81 = "http://jhtmuw1v.beget.tech/build/H.exe"
		$url82 = "http://89.208.104.172/bebra.exe"
		$url83 = "http://jhtmuw1v.beget.tech/build/A.exe"
		$url84 = "http://89.208.104.172/412.exe"
		$url85 = "http://jhtmuw1v.beget.tech/build/3.exe"
		$url86 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg32.jp"
		$url87 = "http://guluiiiimnstrannaer.net/dl/6523.exe"
		$url88 = "http://uaery.top/dl/buildz.exe"
		$url89 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ofg2.jp"
		$url90 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/TjerJeTnHj.jk"
		$url91 = "http://gitcdn.link/cdn/gta11113/fgjhfh/main/ro5io8xv.rt"
		$url92 = "https://mamamiya137.ru/Smart.exe"
		$url93 = "https://cdn.discordapp.com/attachments/1025831078235209788/1034202014403543072/123.exe"
		$url94 = "http://gitcdn.link/cdn/dima11113fg/erty/main/ofg2.jp"
		$url95 = "http://gitcdn.link/cdn/prostoprosto/sdgdfsg/main/ofg.jp"
		$url96 = "https://cdn.discordapp.com/attachments/988460078250205185/1034211170766311485/HyperproviderCommon228.exe"
		$url97 = "http://cghfdyj.b-cdn.net/brave32.exe"
		$url98 = "http://sarlmagsub.com/16/data64_1.exe"
		$url99 = "http://185.223.93.133/conhost.exe"
		$url100 = "http://23.88.123.223/Browser.exe"
		$url101 = "https://mamamiya137.ru/mine/ChomiumPath.exe"

   condition:
        any of them
}
