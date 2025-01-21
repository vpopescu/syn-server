
This is a STUN server implementation I wrote a couple of years ago while learning rust.

I have stopped developing it for now because I could not find good test tools to exercise the STUN protocol, and writing a STUN client myself was not something in the plans. If you can recommend a client or library that support RFC5389 and higher, please let me know.

Mimimum RFC supported is RFC5389. The older RFC3489 is not supported.

Configuration is via config file or environment:

| variable | values | meaning |
| ----------------- | ------ | ------- |
| SYN_COMPLIANCE    |  Relaxed, RFC5389 | Compliance level |
| SYN_DISABLE_TCP   | true | Disable listening for TCP connections |
| SYN_DISABLE_UDP   | true | Disable listening for UDP connections |
| SYN_SOFTWARE_NAME | <string> | Server identifier that will be provided in SOFTWARE_NAME field |

A few other untested ones are defined.

