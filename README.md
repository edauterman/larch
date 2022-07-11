# Larch

Dependencies
* OpenSSL
* gRPC
* emp-toolkit (install in same directory where `larch/` is installed)

Make an `out/` folder.

In `src/config.h`, set `OUT_DIR` to the location of the `out/` folder and `PROJ_DIR` to the location of `larch/`.
Set `LOG_IP_ADDR` to the public IP address of the log (with the port number), and `LOG_BIND_ADDR` to `0.0.0.0:PORT_NUM`.

```
cd network
cmake .
make
cd ..
cmake .
make
```
