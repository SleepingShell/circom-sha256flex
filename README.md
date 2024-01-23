# circom-sha256flex
An implementation allowing a flexible amount of bits into the sha256 hashing function. Callers should instantiate the input signal to the circuit with the number of bits the template was instantiated with.

For example, if `Sha256Flexible(512)` is used, then you should call the input with 512 bits.

A useful tool for quickly seeing the sha256 internal state: https://sha256algorithm.com/