import socket, ssl
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(["http/1.1"])
with socket.create_connection(("p.m1.fastly-masque.net", 2499), timeout=15) as sock:
    with ctx.wrap_socket(sock, server_hostname="p.m1.fastly-masque.net") as tls:
        print("TLS_OK", tls.version(), tls.getpeercert().get("subject").get("commonName"))
