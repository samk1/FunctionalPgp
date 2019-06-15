namespace SolidPgp.Parsing.Tests

type PacketHeaderTestCase = byte[] * string * int64 * int

module PacketHeaderTestCases =
    let cases = [
        [| 128uy; 8uy |], "Tag: RESERVED, Length: 8, Format: Old", 8L, 0
        [| 132uy; 8uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 8, Format: Old", 8L, 1
        [| 136uy; 8uy |], "Tag: SIGNATURE, Length: 8, Format: Old", 8L, 2
        [| 140uy; 8uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 8, Format: Old", 8L, 3
        [| 144uy; 8uy |], "Tag: ONE_PASS_SIGNATURE, Length: 8, Format: Old", 8L, 4
        [| 148uy; 8uy |], "Tag: SECRET_KEY, Length: 8, Format: Old", 8L, 5
        [| 152uy; 8uy |], "Tag: PUBLIC_KEY, Length: 8, Format: Old", 8L, 6
        [| 156uy; 8uy |], "Tag: SECRET_SUBKEY, Length: 8, Format: Old", 8L, 7
        [| 160uy; 8uy |], "Tag: COMPRESSED_DATA, Length: 8, Format: Old", 8L, 8
        [| 164uy; 8uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 8, Format: Old", 8L, 9
        [| 168uy; 8uy |], "Tag: MARKER, Length: 8, Format: Old", 8L, 10
        [| 172uy; 8uy |], "Tag: LITERAL_DATA, Length: 8, Format: Old", 8L, 11
        [| 176uy; 8uy |], "Tag: TRUST, Length: 8, Format: Old", 8L, 12
        [| 180uy; 8uy |], "Tag: USER_ID, Length: 8, Format: Old", 8L, 13
        [| 184uy; 8uy |], "Tag: PUBLIC_SUBKEY, Length: 8, Format: Old", 8L, 14
        [| 196uy; 8uy |], "Tag: USER_ATTRIBUTE, Length: 8, Format: Old", 8L, 17
        [| 200uy; 8uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 8, Format: Old", 8L, 18
        [| 204uy; 8uy |], "Tag: MOD_DETECTION_CODE, Length: 8, Format: Old", 8L, 19
        [| 240uy; 8uy |], "Tag: EXPERIMENTAL_1, Length: 8, Format: Old", 8L, 60
        [| 244uy; 8uy |], "Tag: EXPERIMENTAL_2, Length: 8, Format: Old", 8L, 61
        [| 248uy; 8uy |], "Tag: EXPERIMENTAL_3, Length: 8, Format: Old", 8L, 62
        [| 252uy; 8uy |], "Tag: EXPERIMENTAL_4, Length: 8, Format: Old", 8L, 63
        [| 128uy; 255uy |], "Tag: RESERVED, Length: 255, Format: Old", 255L, 0
        [| 132uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 255, Format: Old", 255L, 1
        [| 136uy; 255uy |], "Tag: SIGNATURE, Length: 255, Format: Old", 255L, 2
        [| 140uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 255, Format: Old", 255L, 3
        [| 144uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 255, Format: Old", 255L, 4
        [| 148uy; 255uy |], "Tag: SECRET_KEY, Length: 255, Format: Old", 255L, 5
        [| 152uy; 255uy |], "Tag: PUBLIC_KEY, Length: 255, Format: Old", 255L, 6
        [| 156uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 255, Format: Old", 255L, 7
        [| 160uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 255, Format: Old", 255L, 8
        [| 164uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 255, Format: Old", 255L, 9
        [| 168uy; 255uy |], "Tag: MARKER, Length: 255, Format: Old", 255L, 10
        [| 172uy; 255uy |], "Tag: LITERAL_DATA, Length: 255, Format: Old", 255L, 11
        [| 176uy; 255uy |], "Tag: TRUST, Length: 255, Format: Old", 255L, 12
        [| 180uy; 255uy |], "Tag: USER_ID, Length: 255, Format: Old", 255L, 13
        [| 184uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 255, Format: Old", 255L, 14
        [| 196uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 255, Format: Old", 255L, 17
        [| 200uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 255, Format: Old", 255L, 18
        [| 204uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 255, Format: Old", 255L, 19
        [| 240uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 255, Format: Old", 255L, 60
        [| 244uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 255, Format: Old", 255L, 61
        [| 248uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 255, Format: Old", 255L, 62
        [| 252uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 255, Format: Old", 255L, 63
        [| 129uy; 255uy; 255uy |], "Tag: RESERVED, Length: 65535, Format: Old", 65535L, 0
        [| 133uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 65535, Format: Old", 65535L, 1
        [| 137uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 65535, Format: Old", 65535L, 2
        [| 141uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 65535, Format: Old", 65535L, 3
        [| 145uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 65535, Format: Old", 65535L, 4
        [| 149uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 65535, Format: Old", 65535L, 5
        [| 153uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 65535, Format: Old", 65535L, 6
        [| 157uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 65535, Format: Old", 65535L, 7
        [| 161uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 65535, Format: Old", 65535L, 8
        [| 165uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 65535, Format: Old", 65535L, 9
        [| 169uy; 255uy; 255uy |], "Tag: MARKER, Length: 65535, Format: Old", 65535L, 10
        [| 173uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 65535, Format: Old", 65535L, 11
        [| 177uy; 255uy; 255uy |], "Tag: TRUST, Length: 65535, Format: Old", 65535L, 12
        [| 181uy; 255uy; 255uy |], "Tag: USER_ID, Length: 65535, Format: Old", 65535L, 13
        [| 185uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 65535, Format: Old", 65535L, 14
        [| 197uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 65535, Format: Old", 65535L, 17
        [| 201uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 65535, Format: Old", 65535L, 18
        [| 205uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 65535, Format: Old", 65535L, 19
        [| 241uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 65535, Format: Old", 65535L, 60
        [| 245uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 65535, Format: Old", 65535L, 61
        [| 249uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 65535, Format: Old", 65535L, 62
        [| 253uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 65535, Format: Old", 65535L, 63
        [| 130uy; 0uy; 255uy; 255uy; 255uy |], "Tag: RESERVED, Length: 16777215, Format: Old", 16777215L, 0
        [| 134uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 16777215, Format: Old", 16777215L, 1
        [| 138uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 16777215, Format: Old", 16777215L, 2
        [| 142uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 16777215, Format: Old", 16777215L, 3
        [| 146uy; 0uy; 255uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 16777215, Format: Old", 16777215L, 4
        [| 150uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 16777215, Format: Old", 16777215L, 5
        [| 154uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 16777215, Format: Old", 16777215L, 6
        [| 158uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 16777215, Format: Old", 16777215L, 7
        [| 162uy; 0uy; 255uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 16777215, Format: Old", 16777215L, 8
        [| 166uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 16777215, Format: Old", 16777215L, 9
        [| 170uy; 0uy; 255uy; 255uy; 255uy |], "Tag: MARKER, Length: 16777215, Format: Old", 16777215L, 10
        [| 174uy; 0uy; 255uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 16777215, Format: Old", 16777215L, 11
        [| 178uy; 0uy; 255uy; 255uy; 255uy |], "Tag: TRUST, Length: 16777215, Format: Old", 16777215L, 12
        [| 182uy; 0uy; 255uy; 255uy; 255uy |], "Tag: USER_ID, Length: 16777215, Format: Old", 16777215L, 13
        [| 186uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 16777215, Format: Old", 16777215L, 14
        [| 198uy; 0uy; 255uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 16777215, Format: Old", 16777215L, 17
        [| 202uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 16777215, Format: Old", 16777215L, 18
        [| 206uy; 0uy; 255uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 16777215, Format: Old", 16777215L, 19
        [| 242uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 16777215, Format: Old", 16777215L, 60
        [| 246uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 16777215, Format: Old", 16777215L, 61
        [| 250uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 16777215, Format: Old", 16777215L, 62
        [| 254uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 16777215, Format: Old", 16777215L, 63
        [| 130uy; 255uy; 255uy; 255uy; 255uy |], "Tag: RESERVED, Length: 4294967295, Format: Old", 4294967295L, 0
        [| 134uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 4294967295, Format: Old", 4294967295L, 1
        [| 138uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 4294967295, Format: Old", 4294967295L, 2
        [| 142uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 4294967295, Format: Old", 4294967295L, 3
        [| 146uy; 255uy; 255uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 4294967295, Format: Old", 4294967295L, 4
        [| 150uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 4294967295, Format: Old", 4294967295L, 5
        [| 154uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 4294967295, Format: Old", 4294967295L, 6
        [| 158uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 4294967295, Format: Old", 4294967295L, 7
        [| 162uy; 255uy; 255uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 4294967295, Format: Old", 4294967295L, 8
        [| 166uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 4294967295, Format: Old", 4294967295L, 9
        [| 170uy; 255uy; 255uy; 255uy; 255uy |], "Tag: MARKER, Length: 4294967295, Format: Old", 4294967295L, 10
        [| 174uy; 255uy; 255uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 4294967295, Format: Old", 4294967295L, 11
        [| 178uy; 255uy; 255uy; 255uy; 255uy |], "Tag: TRUST, Length: 4294967295, Format: Old", 4294967295L, 12
        [| 182uy; 255uy; 255uy; 255uy; 255uy |], "Tag: USER_ID, Length: 4294967295, Format: Old", 4294967295L, 13
        [| 186uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 4294967295, Format: Old", 4294967295L, 14
        [| 198uy; 255uy; 255uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 4294967295, Format: Old", 4294967295L, 17
        [| 202uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 4294967295, Format: Old", 4294967295L, 18
        [| 206uy; 255uy; 255uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 4294967295, Format: Old", 4294967295L, 19
        [| 242uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 4294967295, Format: Old", 4294967295L, 60
        [| 246uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 4294967295, Format: Old", 4294967295L, 61
        [| 250uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 4294967295, Format: Old", 4294967295L, 62
        [| 254uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 4294967295, Format: Old", 4294967295L, 63
        [| 192uy; 8uy |], "Tag: RESERVED, Length: 8, Format: New", 8L, 0
        [| 193uy; 8uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 8, Format: New", 8L, 1
        [| 194uy; 8uy |], "Tag: SIGNATURE, Length: 8, Format: New", 8L, 2
        [| 195uy; 8uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 8, Format: New", 8L, 3
        [| 196uy; 8uy |], "Tag: ONE_PASS_SIGNATURE, Length: 8, Format: New", 8L, 4
        [| 197uy; 8uy |], "Tag: SECRET_KEY, Length: 8, Format: New", 8L, 5
        [| 198uy; 8uy |], "Tag: PUBLIC_KEY, Length: 8, Format: New", 8L, 6
        [| 199uy; 8uy |], "Tag: SECRET_SUBKEY, Length: 8, Format: New", 8L, 7
        [| 200uy; 8uy |], "Tag: COMPRESSED_DATA, Length: 8, Format: New", 8L, 8
        [| 201uy; 8uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 8, Format: New", 8L, 9
        [| 202uy; 8uy |], "Tag: MARKER, Length: 8, Format: New", 8L, 10
        [| 203uy; 8uy |], "Tag: LITERAL_DATA, Length: 8, Format: New", 8L, 11
        [| 204uy; 8uy |], "Tag: TRUST, Length: 8, Format: New", 8L, 12
        [| 205uy; 8uy |], "Tag: USER_ID, Length: 8, Format: New", 8L, 13
        [| 206uy; 8uy |], "Tag: PUBLIC_SUBKEY, Length: 8, Format: New", 8L, 14
        [| 209uy; 8uy |], "Tag: USER_ATTRIBUTE, Length: 8, Format: New", 8L, 17
        [| 210uy; 8uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 8, Format: New", 8L, 18
        [| 211uy; 8uy |], "Tag: MOD_DETECTION_CODE, Length: 8, Format: New", 8L, 19
        [| 252uy; 8uy |], "Tag: EXPERIMENTAL_1, Length: 8, Format: New", 8L, 60
        [| 253uy; 8uy |], "Tag: EXPERIMENTAL_2, Length: 8, Format: New", 8L, 61
        [| 254uy; 8uy |], "Tag: EXPERIMENTAL_3, Length: 8, Format: New", 8L, 62
        [| 255uy; 8uy |], "Tag: EXPERIMENTAL_4, Length: 8, Format: New", 8L, 63
        [| 192uy; 192uy; 63uy |], "Tag: RESERVED, Length: 255, Format: New", 255L, 0
        [| 193uy; 192uy; 63uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 255, Format: New", 255L, 1
        [| 194uy; 192uy; 63uy |], "Tag: SIGNATURE, Length: 255, Format: New", 255L, 2
        [| 195uy; 192uy; 63uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 255, Format: New", 255L, 3
        [| 196uy; 192uy; 63uy |], "Tag: ONE_PASS_SIGNATURE, Length: 255, Format: New", 255L, 4
        [| 197uy; 192uy; 63uy |], "Tag: SECRET_KEY, Length: 255, Format: New", 255L, 5
        [| 198uy; 192uy; 63uy |], "Tag: PUBLIC_KEY, Length: 255, Format: New", 255L, 6
        [| 199uy; 192uy; 63uy |], "Tag: SECRET_SUBKEY, Length: 255, Format: New", 255L, 7
        [| 200uy; 192uy; 63uy |], "Tag: COMPRESSED_DATA, Length: 255, Format: New", 255L, 8
        [| 201uy; 192uy; 63uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 255, Format: New", 255L, 9
        [| 202uy; 192uy; 63uy |], "Tag: MARKER, Length: 255, Format: New", 255L, 10
        [| 203uy; 192uy; 63uy |], "Tag: LITERAL_DATA, Length: 255, Format: New", 255L, 11
        [| 204uy; 192uy; 63uy |], "Tag: TRUST, Length: 255, Format: New", 255L, 12
        [| 205uy; 192uy; 63uy |], "Tag: USER_ID, Length: 255, Format: New", 255L, 13
        [| 206uy; 192uy; 63uy |], "Tag: PUBLIC_SUBKEY, Length: 255, Format: New", 255L, 14
        [| 209uy; 192uy; 63uy |], "Tag: USER_ATTRIBUTE, Length: 255, Format: New", 255L, 17
        [| 210uy; 192uy; 63uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 255, Format: New", 255L, 18
        [| 211uy; 192uy; 63uy |], "Tag: MOD_DETECTION_CODE, Length: 255, Format: New", 255L, 19
        [| 252uy; 192uy; 63uy |], "Tag: EXPERIMENTAL_1, Length: 255, Format: New", 255L, 60
        [| 253uy; 192uy; 63uy |], "Tag: EXPERIMENTAL_2, Length: 255, Format: New", 255L, 61
        [| 254uy; 192uy; 63uy |], "Tag: EXPERIMENTAL_3, Length: 255, Format: New", 255L, 62
        [| 255uy; 192uy; 63uy |], "Tag: EXPERIMENTAL_4, Length: 255, Format: New", 255L, 63
        [| 192uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: RESERVED, Length: 65535, Format: New", 65535L, 0
        [| 193uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 65535, Format: New", 65535L, 1
        [| 194uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 65535, Format: New", 65535L, 2
        [| 195uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 65535, Format: New", 65535L, 3
        [| 196uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 65535, Format: New", 65535L, 4
        [| 197uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 65535, Format: New", 65535L, 5
        [| 198uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 65535, Format: New", 65535L, 6
        [| 199uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 65535, Format: New", 65535L, 7
        [| 200uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 65535, Format: New", 65535L, 8
        [| 201uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 65535, Format: New", 65535L, 9
        [| 202uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: MARKER, Length: 65535, Format: New", 65535L, 10
        [| 203uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 65535, Format: New", 65535L, 11
        [| 204uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: TRUST, Length: 65535, Format: New", 65535L, 12
        [| 205uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: USER_ID, Length: 65535, Format: New", 65535L, 13
        [| 206uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 65535, Format: New", 65535L, 14
        [| 209uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 65535, Format: New", 65535L, 17
        [| 210uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 65535, Format: New", 65535L, 18
        [| 211uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 65535, Format: New", 65535L, 19
        [| 252uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 65535, Format: New", 65535L, 60
        [| 253uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 65535, Format: New", 65535L, 61
        [| 254uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 65535, Format: New", 65535L, 62
        [| 255uy; 255uy; 0uy; 0uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 65535, Format: New", 65535L, 63
        [| 192uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: RESERVED, Length: 16777215, Format: New", 16777215L, 0
        [| 193uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 16777215, Format: New", 16777215L, 1
        [| 194uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 16777215, Format: New", 16777215L, 2
        [| 195uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 16777215, Format: New", 16777215L, 3
        [| 196uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 16777215, Format: New", 16777215L, 4
        [| 197uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 16777215, Format: New", 16777215L, 5
        [| 198uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 16777215, Format: New", 16777215L, 6
        [| 199uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 16777215, Format: New", 16777215L, 7
        [| 200uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 16777215, Format: New", 16777215L, 8
        [| 201uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 16777215, Format: New", 16777215L, 9
        [| 202uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: MARKER, Length: 16777215, Format: New", 16777215L, 10
        [| 203uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 16777215, Format: New", 16777215L, 11
        [| 204uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: TRUST, Length: 16777215, Format: New", 16777215L, 12
        [| 205uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: USER_ID, Length: 16777215, Format: New", 16777215L, 13
        [| 206uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 16777215, Format: New", 16777215L, 14
        [| 209uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 16777215, Format: New", 16777215L, 17
        [| 210uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 16777215, Format: New", 16777215L, 18
        [| 211uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 16777215, Format: New", 16777215L, 19
        [| 252uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 16777215, Format: New", 16777215L, 60
        [| 253uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 16777215, Format: New", 16777215L, 61
        [| 254uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 16777215, Format: New", 16777215L, 62
        [| 255uy; 255uy; 0uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 16777215, Format: New", 16777215L, 63
        [| 192uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: RESERVED, Length: 4294967295, Format: New", 4294967295L, 0
        [| 193uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY_ENC_SESSION, Length: 4294967295, Format: New", 4294967295L, 1
        [| 194uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SIGNATURE, Length: 4294967295, Format: New", 4294967295L, 2
        [| 195uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC_SESSION, Length: 4294967295, Format: New", 4294967295L, 3
        [| 196uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: ONE_PASS_SIGNATURE, Length: 4294967295, Format: New", 4294967295L, 4
        [| 197uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SECRET_KEY, Length: 4294967295, Format: New", 4294967295L, 5
        [| 198uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_KEY, Length: 4294967295, Format: New", 4294967295L, 6
        [| 199uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SECRET_SUBKEY, Length: 4294967295, Format: New", 4294967295L, 7
        [| 200uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: COMPRESSED_DATA, Length: 4294967295, Format: New", 4294967295L, 8
        [| 201uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYMMETRIC_KEY_ENC, Length: 4294967295, Format: New", 4294967295L, 9
        [| 202uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: MARKER, Length: 4294967295, Format: New", 4294967295L, 10
        [| 203uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: LITERAL_DATA, Length: 4294967295, Format: New", 4294967295L, 11
        [| 204uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: TRUST, Length: 4294967295, Format: New", 4294967295L, 12
        [| 205uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: USER_ID, Length: 4294967295, Format: New", 4294967295L, 13
        [| 206uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: PUBLIC_SUBKEY, Length: 4294967295, Format: New", 4294967295L, 14
        [| 209uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: USER_ATTRIBUTE, Length: 4294967295, Format: New", 4294967295L, 17
        [| 210uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: SYM_ENC_INTEGRITY_PRO, Length: 4294967295, Format: New", 4294967295L, 18
        [| 211uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: MOD_DETECTION_CODE, Length: 4294967295, Format: New", 4294967295L, 19
        [| 252uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_1, Length: 4294967295, Format: New", 4294967295L, 60
        [| 253uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_2, Length: 4294967295, Format: New", 4294967295L, 61
        [| 254uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_3, Length: 4294967295, Format: New", 4294967295L, 62
        [| 255uy; 255uy; 255uy; 255uy; 255uy; 255uy |], "Tag: EXPERIMENTAL_4, Length: 4294967295, Format: New", 4294967295L, 63
    ]