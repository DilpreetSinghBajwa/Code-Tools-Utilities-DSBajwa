
rule irc
{
 meta:
 description = "Indicates use of IRC"
	/*The following rule detects malware that utilizes Internet Relay Chat(IRC). Because the strings may exist frequently in files that do not utilize IRC so
	 this rule produces an alert only if any file contains at least four of the strings.
	*/
 
 strings:
 $irc0 = "join" nocase fullword
 $irc1 = "msg" nocase fullword
 $irc2 = "nick" nocase fullword
 $irc3 = "notice" nocase fullword
 $irc4 = "part" nocase fullword
 $irc5 = "ping" nocase fullword
 $irc6 = "quit" nocase fullword
 $irc7 = "chat" nocase fullword
 $irc8 = "privmsg" nocase fullword

 condition:
 4 of ($irc*)
}