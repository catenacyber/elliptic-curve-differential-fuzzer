# ecfuzzer
Differential fuzzing for elliptic curves

Build
------

You can build a standalone binary with classic cmake commands
```
mkdir build
cd build
cmake ..
make
```
This standalone binary expects one argument, a file name, whose contents will be processed.

You can check out `build.sh` from oss-fuzz to build a fuzzing binary.

Architecture
------

List of files :
- main.c : main function for processing one file
- fuzz_ec.c : fuzz target, ie `LLVMFuzzerTestOneInput` function
- fuzz_ec.h : common structures for modules
- modules : directory with one file per module

Processing
------

The input buffer must be at least 4 bytes :
- 2 bytes are used to reference the curve (using the reference identifiers from TLS protocol)
- at least 1 byte for two big integers

For each module, the fuzzer will :
- load the curve (if the module does not know the curve, it is ok)
- do a scalar multiplication of first big integer with curve generator
- check the return code (abort on failure)
- check the result (point coordinates) with the previous module (abort on first difference)
