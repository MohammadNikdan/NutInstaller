
================================================================================
DEPLOYMENT NOTE
================================================================================
Place license-signing-public.pem (the SAME RSA public key PEM already used
server-side to verify signatures - `openssl rsa -pubout` format, i.e. a
"-----BEGIN PUBLIC KEY-----" file) next to this DLL, exactly as you said you
would provide it. MachineId32.dll or MachineId64.dll (matching this DLL's
own bitness) must also be present in the same directory.
