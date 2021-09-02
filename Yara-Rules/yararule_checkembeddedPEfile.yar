rule embedded_exe
{
 meta:
 description = "Detects embedded executables."
 	/*
	The following rule detects embedded PE files, which is a common characteristic of droppers and installers. 
	It produces an alert only if the string is found at an offset greater than 1024 in the file, which is outside of the typical PE header (otherwise it would produce an alert on every PE file). 
	The filesize keyword represents the total number of bytes in the file or data buffer being scanned.
	*/
 strings:
 $a = "This program cannot be run in DOS mode"

 condition:
 $a in (1024..filesize)
}