PoC of nginx [ja4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md) module for fingerprinting TLS and TCP.

- Doesn't require any patches to the nginx or OpenSSL.
- ja4o and ja4t can be disabled at compile time.

Building:
`NGINX_SRC=/usr/src/nginx ./build.sh`

Running (this example):
`nginx -c "$PWD/nginx.conf" -p "$PWD"`

Usage:
Add this to you http.server section and your backend will receive x-ja4* headers (and strip client supplied headers).
```
ja4_header x-ja4;
ja4o_header x-ja4o;
ja4t_header x-ja4t;
```

Test with curl:
`curl --insecure https://localhost:8443/`
`Prints: {"ja4":"t13d3013h2_1d37bd780c83_8537cf56674e","ja4o":"t13d3013h2_8d44cdc55eec_5bd17f9d395a","ja4t":"65495_2-4-8-1-3_65495_10"}`


Useful resources:
https://github.com/FoxIO-LLC/ja4-nginx-module
https://thumbprint.me/
