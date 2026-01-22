# HashLib

HashLib is a **learning focused** collection of cryptographic hash function implementations written in C.

This repository is **not intended for production use**.

## License

This repository is released under the MIT License, unless otherwise stated in individual source files.

Original licenses from referenced implementations are preserved and respected.

## Disclaimer

This code is provided **for educational purposes only**.
Do **not** use it in security critical or production environments.
I am not responsible for any damage or data loss caused by using this code.

## Testing

Basic test programs are provided in the `tests/` directory.
They validate implementations against known test vectors.

Tests can be compiled directly with a C compiler:

```sh
gcc -std=c99 -Iinclude tests/test_sha1.c -o build/test_sha1
```

Test vectors are taken from RFC 3174.
