Farsight sie-nmsg
=================

This is sie-nmsg, a message module plugin for libnmsg implementing various
message types used by Farsight Security's Security Information Exchange.

Note that on Debian systems, binary packages of nmsg, sie-nmsg, and
dependencies are available from
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/).
These packages should be used in preference to building from source on
Debian-based systems.

Building and installing sie-nmsg from source
--------------------------------------------

sie-nmsg has the following dependencies:

* [nmsg](https://github.com/farsightsec/nmsg), version 0.9.0 or higher. Previous
  versions WILL NOT WORK.

* [protobuf-c](https://github.com/protobuf-c/protobuf-c), version 1.0.1 or
  higher. Previous versions WILL NOT WORK.

* [wdns](https://github.com/farsightsec/wdns)

Note that nmsg >= 0.9.0 and sie-nmsg >= 0.17.0 have been designed to use the 1.x
release series of protobuf-c, while previous releases of nmsg and sie-nmsg were
designed to use the 0.x release series of protobuf-c. Make sure you have the
correct version of protobuf-c installed before attempting to build nmsg and
sie-nmsg.

After satisfying the prerequisites, `./configure && make && make install` should
compile and install sie-nmsg to `/usr/local`. If building from a git checkout,
run the `./autogen.sh` command first to generate the `configure` script.
