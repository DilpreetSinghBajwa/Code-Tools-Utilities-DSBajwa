
rule encoding
{
 meta:
 description = "Indicates encryption/compression"
	/*
		The following rule detects malware that is static-linked with Zlib or OpenSSL libraries.
                If you get positive hits with this rule, it’s highly likely that the malware uses encoding
                 and/or encryption to obfuscate its network communications.
	*/

 strings:
 $zlib0 = "deflate" fullword
 $zlib1 = "Jean-loup Gailly"
 $zlib2 = "inflate" fullword
 $zlib3 = "Mark Adler"

 $ssl0 = "OpenSSL" fullword
 $ssl1 = "SSLeay" fullword

 condition:
 (all of ($zlib*)) or (all of ($ssl*))
}