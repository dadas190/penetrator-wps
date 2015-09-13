# penetrator-wps

This is experimental tool that is capable of attacking multiple WPS-enabled wireless access points in real time.

# cmd options
-h Display help
-i <dev> Set monitor mode device to use
-s Scan for WPS enabled APs
-c <channel> Set channel(s)
-e <essid> Set ESSID for next target specified with -b
-b <bssid> Set target(s)
-A Scan for WPS APs and try pixiedust on all of them;
-M Disable attacking multiple APs at once (only -A)
-P Disable pixiewps after M3 is received
-D Disable loading sessions - starts new
-W Wait after every PIN attempt
-v verbose - print info about WPS messages etc
-vv verbose level 2 - print pixiewps data
-t <seconds>Set time limit for scanning (default 10)
-T <ms> Set timeout - when it occurs, resend last packet (default 1)
-R <max> Set maximum resends (default 5)\n");
-S <seconds> Sleep after 10 failures in a row (default 60)
-N Ignore NACKs (debug)