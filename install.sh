#!/bin/sh

# directory in which the main repository of Cuckoo Sandbox can be found
CUCKOODIR=../cuckoo

# target filename - in case of testing with custom dll's one may wish to
# use a different filename, such as "cuckoomon_bson.dll"
CUCKOOMON=cuckoomon.dll

make && cp cuckoomon.dll "$CUCKOODIR/analyzer/windows/dll/$CUCKOOMON"
