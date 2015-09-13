# penetrator-wps

This is experimental tool that is capable of attacking multiple WPS-enabled wireless access points in real time.

# cmd options
-h Display help<br>
-i <dev> Set monitor mode device to use<br>
-s Scan for WPS enabled APs<br>
-c <channel> Set channel(s)<br>
-e <essid> Set ESSID for next target specified with -b<br>
-b <bssid> Set target(s)<br>
-A Scan for WPS APs and try pixiedust on all of them;<br>
-M Disable attacking multiple APs at once (only -A)<br>
-P Disable pixiewps after M3 is received<br>
-D Disable loading sessions - starts new<br>
-W Wait after every PIN attempt<br>
-v verbose - print info about WPS messages etc<br>
-vv verbose level 2 - print pixiewps data<br>
-t <seconds>Set time limit for scanning (default 10)<br>
-T <ms> Set timeout - when it occurs, resend last packet (default 1)<br>
-R <max> Set maximum resends (default 5)\n");<br>
-S <seconds> Sleep after 10 failures in a row (default 60)<br>
-N Ignore NACKs (debug)<br>