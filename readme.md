# SMR-UDP

The SMR-UDP (Secure MR-UDP) implements DTLS above MR-UDP, using the Bouncy Castle DTLS implementation. It is actually in
develop phase, many things can be changed.

## Using

Simply we need the TlsServer and TlsClient interfaces from Bouncy Castle. Implement these intefaces, or override
DefaultTlsServer and DefaultTlsClient with your security configurations and use them in the SecureReliableSocket and
SecureReliableServerSocket constructors.

## Dependencies

It needs only [Bouncy Castle TLS API](https://www.bouncycastle.org/latest_releases.html) and MR-UDP module from the Bitbucket.
