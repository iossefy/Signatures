import "hash"

/*
    Remus Stealer - YARA Detection Rules
    Source: https://github.com/iossefy/signatures
    Author: Youssef @iossefy
    Date: 2026-06-18
*/

private rule Remus_Stealer_Collection_APIs
{
    meta:
        author = "Youssef @iossefy"
        description = "Detects screenshot and clipboard collection API imports commonly used by Remus Stealer"
        date = "2026-06-18"
        malware_family = "Remus Stealer"
        confidence = "low"
        reference = "https://github.com/iossefy/signatures"

    strings:
        $s1 = "BitBlt" ascii wide
        $s2 = "OpenClipboard" ascii wide
        $s3 = "GetClipboardData" ascii wide
        $s4 = "GetDC" ascii wide
        $s5 = "CreateCompatibleBitmap" ascii wide
        $s6 = "GetDIBits" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule Remus_Stealer_ChaCha20_C2_Material
{
    meta:
        author = "Youssef @iossefy"
        description = "Detects Remus Stealer via the embedded ChaCha20 key/nonce used to decrypt the hardcoded C2 server list"
        date = "2026-06-18"
        malware_family = "Remus Stealer"
        confidence = "high"
        reference = "https://github.com/iossefy/signatures"

    strings:
        $chacha_key   = { fd 71 22 10 a2 7d ec fa c5 e9 d3 0d 5c 49 ae 51
                           57 05 fd e9 97 85 19 b9 68 e4 33 2e 32 2d 9b 24 }
        $chacha_nonce = { 38 26 9d b5 69 e6 4e 64 }

    condition:
        uint16(0) == 0x5A4D and
        $chacha_key and $chacha_nonce
}

rule Remus_Stealer_Obfuscated_Registry_Fields
{
    meta:
        author = "Youssef @iossefy"
        description = "Detects stack-initialized, position-XOR-obfuscated JSON field name byte arrays used by Remus Stealer's registry handler (decode to id/Name/Value/Flags/Type/Data/Mode/Result/Success/Failure)"
        date = "2026-06-18"
        malware_family = "Remus Stealer"
        confidence = "medium"
        reference = "https://github.com/iossefy/signatures"

    strings:
        $f_value1  = { 33 db 7a 11 d1 }
        $f_name1   = { 71 5e 2c 02 78 }
        $f_flags   = { 26 d3 91 37 a9 }
        $f_value2  = "`AD(P"
        $f_name2   = "fquE("
        $f_result  = { 2f 17 07 26 d4 ae }
        $f_success = { 76 8c 58 2d 68 99 5d }
        $f_failure = { 27 07 7a 19 39 2a a8 ca }

    condition:
        uint16(0) == 0x5A4D and
        6 of them
}

rule Remus_Stealer_Syscall_Hash_Dispatcher
{
    meta:
        description = "Detects Remus Stealer's NtSyscall hash dispatcher constants used to resolve syscall numbers indirectly instead of calling Nt* APIs directly. I am not sure if this schema is only used in remus stealer so for that reason i gave a low confidence."
        date = "2026-06-18"
        malware_family = "Remus Stealer"
        confidence = "low"
        reference = "https://github.com/iossefy/signatures"

    strings:
        $h_NtQueryInformationProcess = { 18 1b 8f e1 } // 0xE18F1B18
        $h_NtClose                   = { 0b 31 66 e8 } // 0xE866310B
        $h_NtQueryValueKey           = { 66 fa f0 fd } // 0xFDF0FA66
        $h_NtCreateKey               = { eb 93 ce 51 } // 0x51CE93EB
        $h_NtNotifyChangeKey         = { 25 cc e8 96 } // 0x96E8CC25
        $h_NtAlpcCreatePort          = { 67 27 b3 5e } // 0x5EB32767
        $h_NtDelayExecution          = { 23 16 dc 07 } // 0x07DC1623
        $h_NtMapViewOfSection        = { da 74 d1 25 } // 0x25D174DA

    condition:
        uint16(0) == 0x5A4D and
        6 of them
}

rule Remus_Stealer_Combined_Heuristic
{
    meta:
        author = "Youssef @iossefy"
        description = "Combined heuristic match for Remus Stealer requiring multiple independent indicator classes to reduce false positives"
        date = "2026-06-18"
        malware_family = "Remus Stealer"
        confidence = "high"
        reference = "https://github.com/iossefy/signatures"

    condition:
        uint16(0) == 0x5A4D and
        (
            Remus_Stealer_ChaCha20_C2_Material or
            (
                Remus_Stealer_Obfuscated_Registry_Fields and
                Remus_Stealer_Syscall_Hash_Dispatcher
            ) or
            (
                Remus_Stealer_Collection_APIs and
                Remus_Stealer_Syscall_Hash_Dispatcher
            )
        )
}
