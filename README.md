# penetrator-wps

This is experimental tool that is capable of attacking multiple WPS-enabled wireless access points in real time.

# Cmd options
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