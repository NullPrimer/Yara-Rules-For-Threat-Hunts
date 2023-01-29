rule Wcry Slayer
{

// The Hex string is the full kill switch url

	strings:
		$hex_string = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 75 71 65 72 66 73 6f 64 70 39 69 66 6a 61 70 6f 73 64 66 6a 68 67 6f 73 75 72 69 6a 66 61 65 77 72 77 65 72 67 77 65 61 2e 63 6f 6d }

// u.wnry is an executable file used for the below

		$u_wnry = "u.wnry"

		$Wana_Decryptor = "@WanaDecryptor@.exe" wide nocase

		$hex_string2 = { 4D 5A }


// This url is the kill switch for wannacry and is present as a string in the sample found as part of static analysis.

		$killswitch_url = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" fullword wide nocase

	condition:
		any of ($*) and 2 of ($*)

}