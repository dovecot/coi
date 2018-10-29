Compiling
=========

If you downloaded this package using Git, you will first need to run ./autogen.sh to generate the configure script and some other files:

```
./autogen.sh
```

This requires that you have the following software/packages installed:

 - autoconf
 - automake
 - libtool
 - pandoc (not strictly required - you can avoid it by using: PANDOC=false ./configure)
 - GNU make

After this executed successfully or when you downloaded the tarball, configure needs to be executed with the following parameters:

 -  `--with-dovecot=<path>`

    Path to the dovecot-config file. This can either be a compiled dovecot source tree or point to the location where the dovecot-config file is installed on your system (typically in the $prefix/lib/dovecot directory).

When these paremeters are omitted, the configure script will try to find the local Dovecot installation implicitly.

For example, when compiling against compiled Dovecot sources:

```
./configure --with-dovecot=../dovecot-core
```

Or when compiling against a Dovecot installation:

```
./configure --with-dovecot=/usr/local/lib/dovecot
```

As usual, to compile and install, execute the following:

```
make
sudo make install 
```
