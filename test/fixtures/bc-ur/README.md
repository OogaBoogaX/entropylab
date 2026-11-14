# BC-UR reference vectors

Source repository: https://github.com/BlockchainCommons/bc-ur  
Source commit: `4479fb81b2350ae8bafa042a5572b9c64c2c32ca`, file `test/test.cpp`  
License: BSD-2-Clause Plus Patent License, © Blockchain Commons (see LICENSE)

`reference-vectors.json` holds the expected values from the reference
implementation's tests, extracted unchanged: Xoshiro256**, the random
sampler, shuffle, fragment degree and choice, the fountain encoder's parts
(fields and CBOR) and the multipart UR strings. EntropyLab's fountain decoder
is tested against them; none of these values were produced by EntropyLab's
own code.
