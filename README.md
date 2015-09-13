# penetrator-wps

This is experimental tool that is capable of attacking multiple WPS-enabled wireless access points in real time.<br>
It utilizes the pixie-dust attack every time it receives M3 message, unless it is disabled with -P<br>
pixie-dust requires <a href="https://github.com/wiire/pixiewps">pixiewps</a> to be installed.<br>

#installation

First, you need packages libpcap-dev and libssl-dev, install them with apt-get or whatever your distro uses.<br>
If you want the pixie-dust attack to work, you have to install <a href="https://github.com/wiire/pixiewps">pixiewps</a> too.<br>
Then, just run ./install.sh and run 'penetrator'

# cmd options
<b>-h</b> Display help<br>
<b>-i</b> <dev> Set monitor mode device to use<br>
<b>-s</b> Scan for WPS enabled APs<br>
<b>-c</b> <channel> Set channel(s)<br>
<b>-e</b> <essid> Set ESSID for next target specified with -b<br>
<b>-b</b> <bssid> Set target(s)<br>
<b>-A</b> Scan for WPS APs and try pixiedust on all of them;<br>
<b>-M</b> Disable attacking multiple APs at once (only -A)<br>
<b>-P</b> Disable pixiewps after M3 is received<br>
<b>-D</b> Disable loading sessions - starts new<br>
<b>-W</b> Wait after every PIN attempt<br>
<b>-v</b> verbose - print info about WPS messages etc<br>
<b>-vv</b> verbose level 2 - print pixiewps data<br>
<b>-t</b> <seconds>Set time limit for scanning (default 10)<br>
<b>-T</b> <ms> Set timeout - when it occurs, resend last packet (default 1)<br>
<b>-R</b> <max> Set maximum resends (default 5)\n");<br>
<b>-S</b> <seconds> Sleep after 10 failures in a row (default 60)<br>
<b>-N</b> Ignore NACKs (debug)<br>

# attack modes/examples

<b>1. Adding targets manually</b><<br>
This command will attack two APs on channel 1 at the same time, one has BSSID 11:22:33:44:55:66 and second has ESSID "example" and BSSID66:55:44:33:22:11<br>
<b>penetrator -i mon0 -c 1 -b 11:22:33:44:55:66 -e example -b 66:55:44:33:22:11</b><br>
<b>2. Attacking entire channel</b><br>
This will scan for APs on channel 1 and attack them all at the same time<br>
<b>penetrator -i mon0 -c 1</b><br>
<b>3. Attacking all APs in range with pixiewps</b><br>
This will scan all specified channels (or range 1-13 if nothing is specified) and will try pixie-dust attack on all of them.<br>
There is a timeout of 1 minute for every channel, so if it fails to capture M3 message from some APs, it will just skip them.<br>
By default, all APs on the same channel will be attacked at the same time, this can be disabled with <b>-M</b><br>
penetrator -i mon0 -A