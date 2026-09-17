// Original AfterDark starter rules, distributed under this repository's license.
// Indicators warrant investigation; they are not proof of malware.
rule AfterDark_EICAR_Test {
    meta:
        description = "Harmless EICAR antivirus test marker"
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $marker
}

rule AfterDark_Credential_Dumping_Commands {
    meta:
        description = "Credential dumping command indicators (may occur in documentation)"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "lsadump::sam" ascii wide nocase
        $c = "lsadump::dcsync" ascii wide nocase
    condition:
        any of them
}
