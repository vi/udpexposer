Run `udpexposer -s 0.0.0.0:12345` on server `1.2.3.4`, local Wireguard on e.g `127.0.0.1:2222`, client `udpexposer 0.0.0.0:12345 -a 1.2.3.4:12345`
and it will forward UDP connections to `1.2.3.4:12345` to `127.0.0.1:2222`, with distinct sockets for distinct remote peers.

TODO: actually describe and document.

# Security

* Not DoS resistant; may amplify DDoS attacks. I don't recommend running this as a permanent setup.
