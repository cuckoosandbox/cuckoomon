CuckooMon
=========

This is the Cuckoo Sandbox Monitor, one of the core elements of Cuckoo
Sandbox. CuckooMon provides Cuckoo Sandbox the ability to intercept the
execution flow of a potential malicious sample.

Through Cuckoo Sandbox it is able to monitor all kinds of samples, such as
executables, office files (Microsoft Word, Microsoft Excel), PDF files, and
much more; virtually anything that can be ran on windows (in usermode.)

Compilation
===========

Compilation of CuckooMon is easiest on a Linux distribution. In particular,
when running on a recent Ubuntu machine, the *gcc-mingw-w64-i686* package is
required.

Running *make* will compile *cuckoomon.dll*. To replace ("install") Cuckoo's
DLL by a custom cuckoomon.dll one can run the *./install.sh* script. E.g.,
running `./install.sh` will make *cuckoomon.dll* and copy it to the correct
directory in the Cuckoo directory (which by default is assumed to be at
`../cuckoo`.)

Because we switched from diStorm3's disassembler to Capstone disassembler we
no longer support the *i586-mingw32msvc-cc* compiler, which was present in the
*mingw32* package. It may be possible to get it to work, but at this point I
don't see a need for that. Furthermore, compilation under Windows using cygwin
will not work right now. However, this may be 'fixed' with some tweaking.

Authors
=======

- Jurriaan Bremer
- Mark Schloesser
- Claudio Guarnieri
