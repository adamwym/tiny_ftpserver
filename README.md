# tiny_ftpserver
A tiny version of FTP server written in c++
 ## Supported features
* Both PORT mode and PASV mode
* TLS support
* Common usage commands (e.g. LIST,MKD,PUT)
## Requirements
* linux >=2.6
* openssl
* glib 2.0
* CMake
## How to build
```
mv ./tiny_ftpserver.conf /etc/tiny_ftpserver.conf
mkdir build && cd build
cmake ..

#make daemon version
make tiny_ftpserver_daemon

#make debug version
make tiny_ftpserver
```
## Configuration
tiny_ftpserver has a VsFTPd like configure file.  
The default configuration is in tiny_ftpserver.conf.
## License
This software is licensed under the GPL V2.
