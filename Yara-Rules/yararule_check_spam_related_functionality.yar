
rule spam
{
 meta:
 description = "Indicates spam-related activity"
	/*
	The following rule detects attempts to send spam e-mails (or just e-mails in general
	based on SMTP commands). The number of required matches can be increased to detect
	spam or other strings that won’t be found in normal SMTP communication.
	*/

 strings:
 $spam1 = "e-cards@hallmark.com" nocase
 $spam2 = "hallmark e-card" nocase
 $spam3 = "rcpt to:" nocase
 $spam4 = "mail from:" nocase
 $spam5 = "smtp server" nocase
 $spam6 = "cialis" nocase fullword
 $spam7 = "pharma" nocase fullword
 $spam8 = "casino" nocase fullword
 $spam9 = "ehlo " nocase fullword
 $spama = "from: " nocase fullword
 $spamb = "subject: " nocase fullword
 $spamc = "Content-Disposition: attachment;" nocase
 condition:
 3 of ($spam*)
}