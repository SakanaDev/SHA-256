# SHA-256 Algorithm Implementation in Python

This project is an implementation of the **SHA-256 (Secure Hash Algorithm 256-bit)** cryptographic hash function from scratch in Python. SHA-256 is widely used in various security applications and protocols, including TLS, SSL, PGP, SSH, and Bitcoin. It takes an input (or message) and produces a fixed-size 256-bit (32-byte) hash value, typically rendered as a 64-digit hexadecimal number.

The purpose of this project is to demonstrate how SHA-256 works under the hood by breaking down the algorithm into its core components and implementing them step by step.

---

## Table of Contents
1. [What is SHA-256?](#what-is-sha-256)
2. [How SHA-256 Works](#how-sha-256-works)
3. [Project Implementation](#project-implementation)
4. [Code Overview](#code-overview)
5. [Usage](#usage)
6. [Dependencies](#dependencies)
7. [Contributing](#contributing)
8. [License](#license)

---
<a id="what-is-sha-256"></a>
## What is SHA-256?

SHA-256 is a member of the SHA-2 (Secure Hash Algorithm 2) family, designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in 2001. It is a cryptographic hash function that takes an input and produces a fixed-size output (256 bits) that appears random. The output is unique to the input, meaning even a small change in the input will produce a significantly different hash.

SHA-256 is widely used for:
- Data integrity verification
- Digital signatures
- Password hashing
- Blockchain and cryptocurrency (e.g., Bitcoin)

---
<a id="how-sha-256-work"></a>
## How SHA-256 Works

The SHA-256 algorithm processes the input message in blocks of 512 bits (64 bytes) and performs a series of operations to compute the hash. Here’s a high-level overview of the steps:

1. **Padding**: The input message is padded to ensure its length is a multiple of 512 bits.
2. **Message Schedule**: The padded message is divided into 512-bit blocks, and each block is expanded into a schedule of 64 words (32 bits each).
3. **Compression**: The message schedule is processed using a series of logical functions and constants to update the hash state.
4. **Final Hash**: After processing all blocks, the final hash value is computed by concatenating the hash state.

---
<a id="project-implementation"></a>
## Project Implementation

This project implements the SHA-256 algorithm from scratch in Python. The implementation is divided into several functions, each corresponding to a specific step in the algorithm:

1. **Constants**:
   - `K`: A list of 64 constant 32-bit words used in the compression function.
   - `H`: Initial hash values (8 words of 32 bits each).

2. **Helper Functions**:
   - `ROTR(x, n)`: Performs a right rotation on a 32-bit word.
   - `SHR(x, n)`: Performs a right shift on a 32-bit word.
   - `Ch(e, f, g)`: Choice function.
   - `Maj(a, b, c)`: Majority function.
   - `Sig0(a)` and `Sig1(e)`: Sigma functions used in the message schedule.

3. **Padding**:
   - `SHA256_padding(m_bytes)`: Pads the input message to a multiple of 512 bits.

4. **Message Schedule**:
   - `SHA256_extended(m_int_512)`: Expands a 512-bit block into 64 words.

5. **Compression**:
   - `SHA256_compress(H_list, W)`: Processes the message schedule and updates the hash state.

6. **Main Function**:
   - `sha256(m)`: Computes the SHA-256 hash of the input message.

---
<a id="code-overview"></a>
## Code Overview

Here’s a brief explanation of the key components of the code:

### Constants
```python
# Constants for SHA-256 algorithm 
K = [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

# Initial hash values for SHA-256
H = [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]
```
### Helper Functions
```python
def ROTR(x, n):  # Right rotation
    return ((x >> n) | (x << 32-n)) & 0xFFFFFFFF

def SHR(x, n): # Right shift
    return (x >> n) & 0xFFFFFFFF

def Ch(e, f, g):  # Choice function
    return (e & f) ^ (~e & g)

def Maj(a, b, c):  # Majority function
    return (a & b) ^ (a & c) ^ (b & c)

def Sig0(a): # Sigma 0: A combination of rotations and shifts used in SHA-256.
    return (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22))

def Sig1(e): # Sigma 1: A combination of rotations and shifts used in SHA-256.
    return (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e,25))
```
### Padding
```python
def SHA256_padding(m_bytes):
    l = len(m_bytes) * 8  # Length of the message in bits
    k = (448 - (l + 1)) % 512  # Number of padding bits needed

    padded_message = int.from_bytes(m_bytes, 'big')
    padded_message = (padded_message << 1) | 1  # Append a single '1' bit
    padded_message = padded_message << k  # Append 'k' '0' bits

    total_bits = l + k + 1
    padded_message = int(padded_message).to_bytes(int(total_bits / 8), 'big')

    padded_block_64 = int(l).to_bytes(8, 'big')  # Append the length of the original message

    return padded_message + padded_block_64
```
### Messsage Schedule
```python
def SHA256_extended(m_int_512):
    W = [(m_int_512 >> 32 * (15 - t)) & 0xFFFFFFFF for t in range(0, 16)]

    for t in range(16, 64):
        sig0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ SHR(W[t - 15], 3)
        sig1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ SHR(W[t - 2], 10)
        
        W.append((sig1 + W[t - 7] + sig0 + W[t - 16]) & 0xFFFFFFFF)
    
    return W
```
### Compression
```python
def SHA256_compress(H_list, W):
    a, b, c, d, e, f, g, h = H_list

    for t in range(0, 64):
        T1 = (h + Sig1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
        T2 = (Sig0(a) + Maj(a, b, c)) & 0xFFFFFFFF

        h = g & 0xFFFFFFFF
        g = f & 0xFFFFFFFF
        f = e & 0xFFFFFFFF
        e = (d + T1) & 0xFFFFFFFF
        d = c & 0xFFFFFFFF
        c = b & 0xFFFFFFFF
        b = a & 0xFFFFFFFF
        a = (T1 + T2) & 0xFFFFFFFF
    
    H_result = [
        (H_list[0] + a) & 0xFFFFFFFF,
        (H_list[1] + b) & 0xFFFFFFFF,
        (H_list[2] + c) & 0xFFFFFFFF,
        (H_list[3] + d) & 0xFFFFFFFF,
        (H_list[4] + e) & 0xFFFFFFFF,
        (H_list[5] + f) & 0xFFFFFFFF,
        (H_list[6] + g) & 0xFFFFFFFF,
        (H_list[7] + h) & 0xFFFFFFFF
    ]

    return H_result
    ...
```

### Main Function
```python
def sha256(m):
    padded_message = SHA256_padding(m.encode())  # Pad the message

    blocks = []

    # Split the padded message into 512-bit blocks
    for i in range(0, len(padded_message), 64):
        blocks.append(int.from_bytes(padded_message[i:i + 64], 'big'))
    
    H_result = H  # Initialize with the initial hash values
    for block in blocks:
        W = SHA256_extended(block)  # Expand the block
        H_result = SHA256_compress(H_result, W)  # Compress the block

    string_hex = ''.join('{:08x}'.format(x) for x in H_result)
    return string_hex
```
---
<a id="usage"></a>
## Usage
To use the SHA-256 implementation, simply call the `sha256` function with your input message:
```python
message = "Hello, World!"
hash_result = sha256(message)
print(hash_result)
```
the output will be a list of 8 integers representing the 256-bit hash value.
```
output: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
```
---
<a id="dependencies"></a>
## Dependencies
This implementation is written in pure Python and does not require any external libraries.

---
<a id="contributing"></a>
## Contributing
Contributions are welcome! If you found any issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

---
<a id="license"></a>
## License 
This project is open-source.

---
