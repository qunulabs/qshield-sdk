TEST ONLY. NOT A REAL CREDENTIAL.

This self-signed certificate and its private key exist for one purpose: the SDK
test that proves an untrusted server certificate produces the right error. The
key is generated for that test, is committed on purpose, and has never protected
anything. Do not install it in any trust store, do not serve anything real with
it, and do not copy it into any other project.
