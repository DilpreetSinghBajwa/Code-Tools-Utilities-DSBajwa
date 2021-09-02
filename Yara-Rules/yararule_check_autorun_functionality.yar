
rule autorun
{
 meta:
 description = "Indicates attempt to spread through autorun"
	/*
	The following rule detects malware that attempts to spread through autorun functionality. 
	The rule includes strings necessary for building an autorun.inf file that uses the open
	action to execute a program.
	*/

 strings: 
 $a = "[autorun]"
 $b = "open="

 condition:
 all of them
}