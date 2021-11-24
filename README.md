# HTTP-Forward-Proxy
A multi-threaded, HTTP-only forward proxy that handles GET requests, and performs caching and prefetching.  

The project is a part of CSCI 5273: Network Systems.  

## Instructions
The makefile will compile the source code into a file named 'webproxy'. Note that the makefile compiler and linker flags will need to be modified depending on where your OpenSSL library is installed on your computer. 
```
make
```

Once the compilation is done, the executable can be run in the following manner:

### Server
```
./filepath/webproxy [Port Number] [Cache TTL]
```
*Port Number* must be greater than 5000.

**NOTE**: In the above command, 'filepath' must be replaced by the path on your system, based on your current directory. This is especially important because the server looks for files to serve based on that path.

## Authors
* Nimish Bhide
