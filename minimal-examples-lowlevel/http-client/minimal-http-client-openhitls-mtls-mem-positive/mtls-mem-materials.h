/*
 * lws-minimal-http-client-openhitls-mtls-mem-positive material
 *
 * Reuses the local CA / server / client chain created for the file-backed
 * mTLS positive test, but embeds the server leaf cert/key and the full client
 * trust+identity material directly in memory so the OpenHiTLS *_mem branches
 * are exercised on successful handshakes.
 */

#if !defined(LWS_MTLS_MEM_MATERIALS_H)
#define LWS_MTLS_MEM_MATERIALS_H

static const char test_ca_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDMzCCAhugAwIBAgIUMsZezi+y+nudaZeDopmbIKqwrXQwDQYJKoZIhvcNAQEL\n"
	"BQAwITEfMB0GA1UEAwwWb3BlbmhpdGxzLW10bHMtZmlsZS1jYTAeFw0yNjA0MDkw\n"
	"ODM2MjRaFw0zNjA0MDYwODM2MjRaMCExHzAdBgNVBAMMFm9wZW5oaXRscy1tdGxz\n"
	"LWZpbGUtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTQtlqhZhc\n"
	"MJbq8xTjHaNU/a+fGC1HoOul4fFcfhVT5GtSIhFv4uz1Sf6HwspGeeI9X0BE3aR8\n"
	"Le+CIigwRV6AxOUq4VZGJRxcNq4NFY8FG0wVxBsWUbQ29luAYaR1Fgb4DPouZUV5\n"
	"gEZbghfIWDgyYw+zlCSAw9HsQ6EbbIIhw1n7uJOmhdG2nO1tsA3BJNweRM0qleOr\n"
	"n48eCG7rq+fUPueIlVDBvnUREnJhOXq6DU1+79PmAyyLcrtcqjDp6Dz1HXycysAl\n"
	"pIxtRKgfnK7dQYMkmspKxmFw/KLuiyZ1IBYWJwlL4kBfhzjbK/sgEqPfo5BQWCIO\n"
	"kf/d4Q1dc47fAgMBAAGjYzBhMB8GA1UdIwQYMBaAFHhrOZQhPMOn9EIJvstJqL0k\n"
	"Ky0LMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR4\n"
	"azmUITzDp/RCCb7LSai9JCstCzANBgkqhkiG9w0BAQsFAAOCAQEAGrffVXA02N53\n"
	"zC5XldyfIB6Sd7W0qTU96YM/KRzVGZX3aTKK9UNsXOHaeZTRIC6RikqYOYuzlobJ\n"
	"agtH2np34OM043GnVJudb38Z77zfbVqq+n+1IEo7s/gN7BNpl0tPqLP7TbZC/KzE\n"
	"xrCJE753EV9RcefQDk1bEb087d/m1dm9tpa1/AqFUvyp3UEAF/F82axbjMLv40V5\n"
	"P0gxMzXxJW3bF4bzdV76IMXPeD73eg5wwjdosv+ud0eNhxq9SjqRxj+zdzyi4nHT\n"
	"92Omi/knnlrttnIKbrFmFJtxytG88w1tIPJO3WY6JL39qA9sv4Bxgy8eoGEhLbEk\n"
	"TLcjBTbNzw==\n"
	"-----END CERTIFICATE-----\n";

static const char test_server_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDVjCCAj6gAwIBAgIUe1zu74SK3dTZ5ruQn9vFBjOEPPIwDQYJKoZIhvcNAQEL\n"
	"BQAwITEfMB0GA1UEAwwWb3BlbmhpdGxzLW10bHMtZmlsZS1jYTAeFw0yNjA0MDkw\n"
	"ODM2MjRaFw0zNjA0MDYwODM2MjRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIw\n"
	"DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMv5hX8Ag0Q39XLEYigdSAtR9+YO\n"
	"H/p4Yt0LpbpdntP1hW0V2agh+wearcR6/lMCtBvDs2NjSpk32IGT1Q4t33j3DxrT\n"
	"qeFIv9mtB5nXbKgJdBnpnn06B12RzgIaFP6IIIbzuwW3iT9N3SfE9E9xZcLXVCXT\n"
	"Jw26eh7elxrvsd6axAflTr1fOBK4iQH1RYMKRv7Y4N6ZhoZXlgplCyrGyjgPrDAA\n"
	"yDNWh/33LEiLiW7mL4c5QYo47SA1NhKyvxZ0v/snYG3ZPJM8CkA4TPIkaPKoabn/\n"
	"G3022MYSPXG1jGMyI9wmyZsFziramCWYr3uSDmGI/ywWQKI6Ql1LsguOU7UCAwEA\n"
	"AaOBkjCBjzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\n"
	"BggrBgEFBQcDATAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwHQYDVR0OBBYE\n"
	"FID01CYESVEo+jLzKtReDys2CdpuMB8GA1UdIwQYMBaAFHhrOZQhPMOn9EIJvstJ\n"
	"qL0kKy0LMA0GCSqGSIb3DQEBCwUAA4IBAQAJYZOdq8hayRovRptvkMDZFJhD8I3n\n"
	"mzC1izEVzUfXQxd/7VsXBNVf3m8u9LVCuxjEbFacOOeygcYx6/tBLgWX/TRa2bl5\n"
	"nEc5UHSldPcnq7unhfyC8B5vadQOAcK9Rl+ymhrz0FI2DhNFL4qE4nHoyisvklGc\n"
	"wP4zC4ozAntw6gzV5fhQIqPEHvRf649nQ8i+40Saj6kuzCsnH7xB9yofNFM8UgoZ\n"
	"vgrrtFc+vymMDx43PH7B2h6Ph3N0qwojZ+l5nHXzcSknwB36jwKUqjaerlbj7Qrx\n"
	"x76dEs88hhlMAPeLP3gc/EQZx9u48+NFhFoIdzGt72UhhAxC/ZUV6xqd\n"
	"-----END CERTIFICATE-----\n";

static const char test_server_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDL+YV/AINEN/Vy\n"
	"xGIoHUgLUffmDh/6eGLdC6W6XZ7T9YVtFdmoIfsHmq3Eev5TArQbw7NjY0qZN9iB\n"
	"k9UOLd949w8a06nhSL/ZrQeZ12yoCXQZ6Z59Ogddkc4CGhT+iCCG87sFt4k/Td0n\n"
	"xPRPcWXC11Ql0ycNunoe3pca77HemsQH5U69XzgSuIkB9UWDCkb+2ODemYaGV5YK\n"
	"ZQsqxso4D6wwAMgzVof99yxIi4lu5i+HOUGKOO0gNTYSsr8WdL/7J2Bt2TyTPApA\n"
	"OEzyJGjyqGm5/xt9NtjGEj1xtYxjMiPcJsmbBc4q2pglmK97kg5hiP8sFkCiOkJd\n"
	"S7ILjlO1AgMBAAECggEAHlrW1AymfEt7moXBOckJxK2BH9pwRd0OkWi/VBnEnjSG\n"
	"k7JRvuS3r+0D+R54pK/dT9hy5NKM8npOHRJ7/W00OZNCyzI+sMkby/AlFm7pu6QU\n"
	"hBqxPF+bYwBk0QlCoJJvjMXOyk4C/cm/pMB5vyzYAQP8gNiIklFzBQ8JG7gaF09a\n"
	"331imJ635A+BCrk6+z1ajVNph/3ly6ohYPEl/ycwIT3//HC9m77aF8JIJ7Tr7MEw\n"
	"AeCaejYr+aIINKXbaQCGESKNpnsAMUK8lcfGbCv5FJKgBkgW2d7TxCoftGRA0Yey\n"
	"uIn5SPkPxX0rnn7AkcKfF15ICMrx9BibVdrnxzZArQKBgQDpcHpY6QBPOrm7nCV1\n"
	"IAATL19iUzcHOpgIAp+w+cfQkzcYQgOtgwgCDcug6qgBeyua+VFXp1wdEWRn6Ncb\n"
	"vw8wqSiL2H6BsnRzaX2oKHICPiXeIbcm7XnPasUDpij+RmiLHSzITFKX7t6JmLEL\n"
	"4bXd0FeBA+rR920l1+4K5o4vlwKBgQDfsA7ntTSpngdUkhXnoWxgai7mei5LfkCD\n"
	"ARBRtIw8fLV6U3IXf/iyBPLt0xXpShU410e8qkfFEKBoWsiAYd8dM5Vlf+R2rZIt\n"
	"iwuxd5ujJAVFxte2xiInmE5AvMW37oY8omZxDEhckZT6DypjCvxE4jZP2lgI7XUQ\n"
	"LBAL1H8AkwKBgGtYrtpd4yeL8McGKe9vVLl9ylYTwDVRy4G7eyXN5wXR/L7p9HkA\n"
	"zVjscRxBbBqqQkYUqkQtkN1JFyv1VZ3LwTd2Qk/0sVAA+S3tb7w5RRwk6hL43BlJ\n"
	"kP9BsPFZonYzeHWoZ+R/vGdjj/AkSB4XoCMtYF/SplQBfK6vWianGPFnAoGBAJVS\n"
	"bRDGiUo1YQVWo+LFgph2KarXozHoLN6HBkLUuMzkHy1yqPYBCp6j6RtTzwu11abl\n"
	"J1FNhq2JpNskxzXUn+FZfwCLuJJ02eEnMf4dLztfn1luHLA5YbF23b4fhgl75AZ0\n"
	"Dtimb2PEF2Q6XXxSaAb/z2vNAPmssnnCQE/1YXabAoGAcqFOt/BhScK6xykPKXgP\n"
	"vLd81LkAPXX9RQJLUVbuSvI1YswaNEh+dv9XaRzlLt1v+Ehawy7la1lj6mHAbLFE\n"
	"PbeywjtqGOZqVyXXbWmckKUsxPSRyz7bRwnnDjKSQb702xvH3e6WMOtY9rP/OXzc\n"
	"b5OmrGjrPuJR0CZ5aHLeQS0=\n"
	"-----END PRIVATE KEY-----\n";

static const char test_client_cert_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDSTCCAjGgAwIBAgIUe1zu74SK3dTZ5ruQn9vFBjOEPPMwDQYJKoZIhvcNAQEL\n"
	"BQAwITEfMB0GA1UEAwwWb3BlbmhpdGxzLW10bHMtZmlsZS1jYTAeFw0yNjA0MDkw\n"
	"ODM2MjRaFw0zNjA0MDYwODM2MjRaMCUxIzAhBgNVBAMMGm9wZW5oaXRscy1tdGxz\n"
	"LWZpbGUtY2xpZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4bbj\n"
	"KX2cOKcqqRhbSkXvIi+PufhSBtch0+2IICV2IsAy120T8e8Qu3Ls+Q8r0ROUeRXZ\n"
	"rMzbSg/73Pk97QTi5dLP0xKgXbMt7/vkPVHJ20yKNlfDWpiXUyoFUES4okwgMrNZ\n"
	"hYaTRAk6bKPHIcSPv3bwA06kuwAsByXaDBXs2XHDkOHLxos0aF8BqeGNlZJbwOtx\n"
	"axlfq2HXm0i2xFEST7EUS3VraUKrVgjFr0j9cL50fxdvUvMhjERXuDuKupkukGgU\n"
	"Kg8YSfWjDJW2SK9oiE2IAgomuw2YmInwvNZn6v1rR1jvcnbDHOKP10thH/dLEWY1\n"
	"vV4OSf0379wONMHoVQIDAQABo3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE\n"
	"AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUISpE6eKrYFDw66OD\n"
	"ojXKxze0rZUwHwYDVR0jBBgwFoAUeGs5lCE8w6f0Qgm+y0movSQrLQswDQYJKoZI\n"
	"hvcNAQELBQADggEBAKdldGjRdL6NqqGqCv7tTr3nFLI2ma/asc41aaRyJT5m2obd\n"
	"coeq3VCujHkbzNcZ0wnHiPNQwZbiKEkhNkhwCOmpjJJLsSGtW/mqfIhGyJBNOIHa\n"
	"RZn4dWscusgiIg6q2Xx9QEpKkBadV4F8GxZxmKGvkPnfzpcBMYwaTg1BNRasaHFJ\n"
	"4SjN1XHQQEkXMW9c28NA8nm1Czprs5v1Xqt3Cv2PWZZM8GKaHVYBDiokV8dl7u+Z\n"
	"vDfbOs7xkJEI1PalzqoKOkAobzR6n9IaDrofEnT/FeHrwZv47R7FsqwT5jjPJsLl\n"
	"YqIWqU/sVsJmagHdRc1MhA0T1n7IOFMg7/P/z7o=\n"
	"-----END CERTIFICATE-----\n";

static const char test_client_key_pem[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDhtuMpfZw4pyqp\n"
	"GFtKRe8iL4+5+FIG1yHT7YggJXYiwDLXbRPx7xC7cuz5DyvRE5R5FdmszNtKD/vc\n"
	"+T3tBOLl0s/TEqBdsy3v++Q9UcnbTIo2V8NamJdTKgVQRLiiTCAys1mFhpNECTps\n"
	"o8chxI+/dvADTqS7ACwHJdoMFezZccOQ4cvGizRoXwGp4Y2VklvA63FrGV+rYdeb\n"
	"SLbEURJPsRRLdWtpQqtWCMWvSP1wvnR/F29S8yGMRFe4O4q6mS6QaBQqDxhJ9aMM\n"
	"lbZIr2iITYgCCia7DZiYifC81mfq/WtHWO9ydsMc4o/XS2Ef90sRZjW9Xg5J/Tfv\n"
	"3A40wehVAgMBAAECggEAAlQEm9Tz25G92uipaGa4RL4A2YY6Ml/dtXXpxYsdYNZi\n"
	"r94sKn6wyX4x+4+wgAOXsHgNOr8SM/1eN7VKcjtuq7g09JRomw7SFnueqxNA5cYw\n"
	"Vsco+LJCPVVdoKpUzTfDzUIUVlBBDJ6bv6sgzrRcVzk+2InjIRqrWZeGXEGNo+CH\n"
	"kdryHLAJ/7NKvjpzwyQmUNGhdvtt/sDNreym5a7UZUQZKmKRa+MwUotlZ4wWAE1M\n"
	"15TbiaGvxSu98W4SWRcf+Q6+WBzIotpVrBLN90tfOrbc6t79w9zjejE2szw8R2P5\n"
	"EwbwdWls75McbE7/8C9UWySScCf4ZaFujGyrFReWAQKBgQD3XajJr4SdxK95PK9d\n"
	"E1FDd0KmDyjT0BL7XIqIVy8dcSjfIbn4Uf8oLeGrwMjcxYwcOMWh9rM0BVdiGMNk\n"
	"1k6f2u353NXHCijiN9SFnFox5nrfpfdEmfKi/4cfaFXDopV6s28vOSgA99i7Ek6D\n"
	"NZ6cTYZc4ImZHn7HlhaITRB09QKBgQDpl8Ld3622jHmW/62mDynSPY+xYCUxqEKU\n"
	"BExCv8rTgfFShLh+R4GKEw1ef1svq3YTxm7qtqx2SoTGOHUz15136vsWMMXo3bpg\n"
	"fLdUO7tDeaVactSJMMNZ7BAc5lNhxgnYuENRgtGoA7H5WCQocvSAYpOCPmEfvDiw\n"
	"yKXmL2SJ4QKBgBH+Jwvcj3nmV5kq99p+UDfnEdsAWUjm5qqP9aerJ8stcvqf+mX8\n"
	"mOG0TKjwkeu1Ftbqrj10s15CUTPad0P7bqakBxFYpdgffg/OXdAGKm1cxW1FJjJA\n"
	"PGzsx0haj3p2dgcBzEGUF7vSS1p4H2vd15ao8PAKiRexJymfWi455MuNAoGAbg7g\n"
	"82TWFfJtv2VLzbfLPpFeyHXCUHk0lUTJIZH34FuS9gwuWOEb+ZAsdl+O+RDSG1Md\n"
	"I11aOIm3sSUco4ZtXPjLwJLOTH9btuZMAlX6TzpbXBhKZzEgeZetp9AlbSW/sepv\n"
	"XVJDseO70P1kW+J9rJfFZFI7tJYcJ78B20htGEECgYAXYWWuCambYl1lsQkV8Dtb\n"
	"1xJSmUBc6cRAODKKJZSRXBxYRf5TKIrNyviAco7eEllZ6HibykEAMXTbgBj1t/Yt\n"
	"3bqwxwYliKA0xorSILSxyC8GnG/T1nmZHLEfDzHgTFrQMilJ4K3TnUn63ruDQdV6\n"
	"HKImBJULLb4denHxMlCSgQ==\n"
	"-----END PRIVATE KEY-----\n";

#endif
