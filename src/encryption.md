# SBU Encryption Algorithm

Key size: $64$ bit
Block size: $32$ bit

## Notation

If `T` is an array, then `T[N]` is the `N`th element
of `T` indexed at 0. 

If `T` is an integral type, then `T[b:a]` is the range
of bits from the `a`th least significant bit inclusive to the `b`th least significant bit inclusive.

## Key Expansion

### Predefined table for key expansion

```C
// UINT32_MAX * fractional part of sqrt of the first 64 primes
block_t T[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};
```

### Generating Key Schedule

Let `T` be the predefined table shown above. Let `S` be the key schedule, an array of blocks of size $32$. Let `K` be the input key.

**Step 1**
```
// Load the key to key schedule 
S[0] := K[31:0]
S[1] := K[63:32]
```
**Step 2**
```
// Generate key schedule, iterating forward
for i in 2,..., 32:
    S[i] = T[ (S[i - 1] XOR S[i - 2]) % 32 ] XOR S[i - 1]
```
**Step 3**
```
// Generate key schedule, iterating backward
for i in 29,..., 0:
    S[i] = T[ (S[i + 1] XOR S[i + 2]) % 32 ] XOR S[i]
```

## Encryption

Let `S` be the key schedule. Let `B` be the input block.

### Bit Operations

1. 8-bit bitwise rotate left `rotl(x, shamt)`
    - Shifts 8-bits `x` left by `shamt` and wrap the bits that "fall off" the left end back around to the right. 
    - For example, 8-bit rotate `0b10110010` left by `3` is `0b10010101`
2. 32-bit reverse `reverse(x)`
    - Reverses the bit order of `x`
    - For example, 8-bit reverse `0b10110010` is `0b01001101`
3. 32-bit interleave every four bits `shuffle4(x)`
    - Interleave every four bits from the lower 16 bits and the upper 16 bits.
    - More precisely, let `x` be the concatenated `abcdefgh` where letter `a` to `h` represents a hexadecimal value. The result of `shuffle4` is `aebfcgdh`
    - For example, `shuffle4(0x76543210) = 0x73625140`
4. 32-bit interleave every bit `shuffle1(x)`
    - Interleave every bit from the lower 16 bits and the upper 16 bits.
    - More precisely, let `x` be the concatenated bitstring `abcdefghijklmnopABCDEFGHIJKLMNOP` where
    the letter represent a bit value. The result of `shuffle1` is `aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP`
    - For example, `shuffle1(0xFFFF0000) = 0xAAAAAAAA` and `shuffle1(0x76543210) = 0x2F2C2320`

### Encryption Subprocedures

`op` is an bijective function between 32-bit integers.

```
rot_table := [ 2, 3, 5, 7 ]

byte(B, i)
    idx = i mod 4
    ret B[8*(idx + 1)-1 : 8*idx]

scramble_op(B, i, keyA, keyB)
    B1 = byte(B, i) XOR ( byte(B, i-1) AND byte(B, i-2) ) XOR ( ~byte(B, i-1) AND byte(B, i-3) ) XOR byte(keyA, i) XOR byte(keyB, i)
    return rotl( B1, rot_table[i] )

mash_op(B, i, S)
    key = S[ byte(B, i-1) mod 32 ]
    ret byte(B, i) XOR byte(key, i)

scramble(B, S, j, op)
    keyA := S[j]
    keyB := S[31 - j]
    B := op(B)
    B[8:0]   := scramble_op(B, 0, keyA, keyB)
    B[16:8]  := scramble_op(B, 1, keyA, keyB)
    B[24:16] := scramble_op(B, 2, keyA, keyB)
    B[32:24] := scramble_op(B, 3, keyA, keyB)
    ret B

mash(B, S)
    B[7:0]   := mash_op(B, 0, S)
    B[15:8]  := mash_op(B, 1, S)
    B[23:16] := mash_op(B, 2, S)
    B[31:24] := mash_op(B, 3, S)
    ret B
```

Note the modulo operation. Unlike the `%` operator in C, the result of the modulo will always be positive. For example, `-1 mod 4 = 3` while `-1 % 4 = -1`.

### Block Encryption Algorithm

```
encrypt_block(B, S)
    R01 := scramble(B, S, 0, reverse)
    R02 := scramble(R01, S, 1, shuffle1)
    R03 := scramble(R02, S, 2, shuffle4)
    R04 := scramble(R03, S, 3, reverse)
    R05 := mash(R04, S)
    R06 := scramble(R05, S, 4, reverse)
    R07 := scramble(R06, S, 5, shuffle1)
    R08 := scramble(R07, S, 6, shuffle4)
    R09 := scramble(R08, S, 7, reverse)
    R10 := mash(R09, S)
    R11 := scramble(R10, S, 8, reverse)
    R12 := scramble(R11, S, 9, shuffle1)
    R13 := scramble(R12, S, 10, shuffle4)
    R14 := scramble(R13, S, 11, reverse)
    R15 := mash(R14, S)
    R16 := scramble(R15, S, 12, reverse)
    R17 := scramble(R16, S, 13, shuffle1)
    R18 := scramble(R17, S, 14, shuffle4)
    R19 := scramble(R18, S, 15, reverse)
    ret R19
```

## Decryption

Decryption involves performing the inverse operations in reverse order.

Let `S` be the key schedule. Let `B` be the input block.

### Bit Operations

1. 8-bit bitwise rotate right `rotr(x, shamt)`
    - Shifts 8-bits `x` right by `shamt` and wrap the bits that "fall off" the right end back around to the left. 
    - For example, 8-bit rotate `0b10110010` right by `3` is `0b01010110`
2. 32-bit un-interleave every four bits `unshuffle4(x)`
    - Inverse operation of `shuffle4`.
    - More precisely, let `x` be the concatenated `aebfcgdh` where letter `a` to `h` represents a hexadecimal value. The result of `unshuffle4` is `abcdefgh`
    - For example, `unshuffle4(0x73625140) = 0x76543210`
3. 32-bit un-interleave every bit `shuffle1(x)`
    - Inverse operation of `shuffle1`
    - More precisely, let `x` be the concatenated bitstring `aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP` where
    the letter represent a bit value. The result of `unshuffle1` is `abcdefghijklmnopABCDEFGHIJKLMNOP`
    - For example, `shuffle1(0xAAAAAAAA) = 0xFFFF0000` and `shuffle1(0x2F2C2320) = 0x76543210`

Note the inverse function of reverse is itself.

### Decryption Subprocedures

```
r_rot_table := [ 7, 5, 3, 2 ]

byte(B, i)
    idx = i mod 4
    ret B[8*(idx + 1)-1 : 8*idx]

r_scramble_op(B, i, keyA, keyB)
    B1 = rotr(B, r_rot_table[i])
    ret byte(B1, i) XOR ( byte(B1, i-1) AND byte(B1, i-2) ) XOR ( ~byte(B1, i-1) AND byte(B1, i-3) ) XOR byte(keyA, i) ^ byte(keyB, i)

r_scramble(B, S, j, op)
    keyA := S[j]
    keyB := S[31 - j]
    B[32:24] := r_scramble_op(B, 3, keyA, keyB)
    B[24:16] := r_scramble_op(B, 2, keyA, keyB)
    B[16:8]  := r_scramble_op(B, 1, keyA, keyB)
    B[8:0]   := r_scramble_op(B, 0, keyA, keyB)
    B := op(B)
    ret B

r_mash(B, S)
    B[32:24] := mash_op(B, 3, S)
    B[24:16] := mash_op(B, 2, S)
    B[16:8]  := mash_op(B, 1, S)
    B[8:0]   := mash_op(B, 0, S)
    ret B
```

### Block Decryption Algorithm

```
decrypt_block(B, S)
    R01 := r_scramble(B, S, 15, reverse)
    R02 := r_scramble(R01, S, 14, unshuffle4)
    R03 := r_scramble(R02, S, 13, unshuffle1)
    R04 := r_scramble(R03, S, 12, reverse)
    R05 := r_mash(R04, S)
    R06 := r_scramble(R05, S, 11, reverse)
    R07 := r_scramble(R06, S, 10, unshuffle4)
    R08 := r_scramble(R07, S, 9, unshuffle1)
    R09 := r_scramble(R08, S, 8, reverse)
    R10 := r_mash(R09, S)
    R01 := r_scramble(R10, S, 7, reverse)
    R02 := r_scramble(R11, S, 6, unshuffle4)
    R03 := r_scramble(R12, S, 5, unshuffle1)
    R04 := r_scramble(R13, S, 4, reverse)
    R15 := r_mash(R14, S)
    R01 := r_scramble(R15, S, 3, reverse)
    R02 := r_scramble(R16, S, 2, unshuffle4)
    R03 := r_scramble(R17, S, 1, unshuffle1)
    R04 := r_scramble(R18, S, 0, reverse)
    ret R19
```

## Encrypting and Decrypting a Stream

The prototype of the encryption and decryption functions is:

```C
void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys);
void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys);
void sbu_decrypt(block_t *encrypted_input, uint8_t *plaintext_output, size_t pt_len, uint32_t *expanded_keys);
```

- `sbu_expand_keys` performs the key expansion step with the input `key` and stores the result in 
`expanded_keys`, an array of 32 blocks. 
    - This only needs to be performed whenever there is a new key. This does not need to be called 

- `sbu_encrypt` encrypts the bytes in the buffer `plaintext_input` using the `expanded_keys` which was written by `sbu_expand_keys`.
If the length of the `plain_text`, here `pt_len`, is not a multiple of four, then it is padded with `0` until it is. The encrypted output is written
to the appropriately sized `encrypted_output`.
    - To create a block for encryption from `plaintext_input`, every four consecutive bytes of `plaintext_input` is concatenated together where the bytes
    that occur earlier in the buffer have a lower address in the block (little endian). For example, the bytes `[0xAA, 0xBB, 0xCC, 0xDD]` would become the block `0xDDCCBBAA`.

- `sbu_decrypt` decrypts the bytes in the buffer `encrypted_input` using the `expanded_keys` which was written by `sbu_expand_keys`. The decrypted byte buffer
may be larger than the `pt_len`, the expected length of the plaintext. If this happens, truncate the remaining bytes. 
    - To decompose the block from the decryption, store the lower bytes in lower addresses (little-endian). In other words, the block `0xDDCCBBAA` would decompose to 
    `[0xAA, 0xBB, 0xCC, 0xDD]`

