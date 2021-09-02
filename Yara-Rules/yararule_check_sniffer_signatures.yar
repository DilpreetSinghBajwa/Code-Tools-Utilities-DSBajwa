
rule sniffer
{
 meta:
 description = "Indicates network sniffer"
	/*
	The following rule detects attempts to sniff network traffic based on the existence of “sniffer” in the file.
	It also detects the names of WinPcap API functions, since many malware families drop or download WinPcap DLLs for sniffing packets.
	*/

 strings:
 $sniff0 = "sniffer" nocase fullword
 $sniff1 = "rpcap:////" nocase
 $sniff2 = "wpcap.dll" nocase fullword
 $sniff3 = "pcap_findalldevs" nocase
 $sniff4 = "pcap_open" nocase
 $sniff5 = "pcap_loop" nocase
 $sniff6 = "pcap_compile" nocase
 $sniff7 = "pcap_close" nocase
 condition:
 any of them
}