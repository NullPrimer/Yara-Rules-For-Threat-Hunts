rule Chimera Stopper
{
	strings:
		$find_http = "http"
		$shady_domain = "whatismyipaddress" fullword

	codition:
		$find_http
		$shady_domain
}