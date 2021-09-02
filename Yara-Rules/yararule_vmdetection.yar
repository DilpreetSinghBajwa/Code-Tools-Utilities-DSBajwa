rule vmdetect
{       
    meta:
	description = "Detects VMs/EMUs/Mons"
         /*
		The following rule detects several attempts to identify virtual machines, emulators,
		sandboxes, or behavior-monitoring applications. 
         */	 
    strings:
        $vm0 = "VIRTUAL HD" nocase
	$vm1 = "VMWARE VIRTUAL IDE HARD DRIVE" nocase
	$vm2 = "QEMU HARDDISK" nocase
	$vm3 = "VBOX HARDDRIVE" nocase
	$vm4 = "The Wireshark Network Analyzer" nocase
	$vm5 = "C:\\sample.exe"
	$vm6 = "C:\\windows\\system32\\sample_1.exe"
	$vm7 = "Process Monitor - Sysinternals: www.sysinternals.com"
	$vm8 = "File Monitor - Sysinternals: www.sysinternals.com"
	$vm9 = "Registry Monitor - Sysinternals: www.sysinternals.com"

    condition:
        all of them
}