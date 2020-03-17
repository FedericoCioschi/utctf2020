Random ECB - UTCTF2020
===

#### Challenge description
- `nc ecb.utctf.live 9003`
- server.py

#### Server code
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from secret import flag

KEY = get_random_bytes(16)


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encryption_oracle(plaintext):
    b = getrandbits(1)
    plaintext = pad((b'A' * b) + plaintext + flag, 16)
    return aes_ecb_encrypt(plaintext, KEY).hex()


if __name__ == '__main__':
    while True:
        print("Input a string to encrypt (input 'q' to quit):")
        user_input = input()
        if user_input == 'q':
            break
        output = encryption_oracle(user_input.encode())
        print("Here is your encrypted string, have a nice day :)")
        print(output)
```

#### Usage example
```
$ nc ecb.utctf.live 9003

Input a string to encrypt (input 'q' to quit):
Hi
Here is your encrypted string, have a nice day :)
48784118b98461daa83a59fb03691192a058f7512f527701bb8d1d1742c34b793c2c3c4a8ba7472c02aa58df82a424c4
Input a string to encrypt (input 'q' to quit):
q
```

#### Solution
So user input is concatenated with the flag and then encrypted using AES-128 in [**ECB mode**](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)).
AES itself is a secure block cipher but ECB mode of operation is not secure.
As stated on Wikipedia:
> The disadvantage of this method is a lack of diffusion. Because ECB encrypts identical plaintext blocks into identical ciphertext blocks, it does not hide data patterns well.

So the idea is to exploit this weakness to brute force flag bytes one by one.

When an input string like `s0m3_t3xt` is sent to the server, this is how plaintext looks like before server-side encryption:

|  B0   |  B1   |  B2   |  B3   |  B4   |  B5   |  B6   |  B7   |  B8   |  B9   |  B10  |  B11  |  B12  |  B13  |  B14  |  B15  |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **s** | **0** | **m** | **3** | **_** | **t** | **3** | **x** | **t** | u     | t     | f     | l     | a     | g     | {     |
| F     | L     | A     | A     | A     | A     | A     | A     | A     | A     | A     | A     | A     | A     | A     | A     |
| A     | A     | A     | A     | A     | G     | }     | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |

Server pads plaintext with [**PKCS #7 padding**](https://en.wikipedia.org/wiki/PKCS) and breaks it in blocks of 16 bytes.
This is only an ideal image of what happens because there's a 50% probability that server puts an `A` byte before user input.
This is the reason why every script below needs a certain number of attempts to be sure that this ideal situation occurs at least once. `ATTEMPTS = 10` seems to be good value to achieve this goal.

First of all, it is necessary to discover the flag length.
I have used this simple script.
```python
#! python3

from pwn import remote

p = remote("ecb.utctf.live", 9003)

ATTEMPTS = 10

def attempt(i):
    p.recvline()
    p.sendline("P"*i)
    p.recvline()
    return len(p.recvline()[:-1])//2
    # NOTE: response is in hexadecimal format, two digits for each byte

minimum_length = min([attempt(0) for j in range(ATTEMPTS)]) - 16

i=1
while True:
    length = min([attempt(i) for j in range(ATTEMPTS)]) - 16
    if length>minimum_length:
        print("Length: {} bytes".format(length-i))
        break
    i+=1
p.sendline('q')
```

```
$ ./flag_length.py
Length: 30 bytes
```

Now the idea is to send properly constructed payloads to the server in order to brute force flag bytes one by one.
They will be discovered in reverse order.
For example, to find out the first byte, the payload is organized like this:
|   |  B0   |  B1   |  B2   |  B3   |  B4   |  B5   |  B6   |  B7   |  B8   |  B9   |  B10  |  B11  |  B12  |  B13  |  B14  |  B15  |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| 1° | ***GUESS*** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |
| 2° | PUSH     | PUSH   | PUSH   |

In this way server-side plaintext takes this form:
|   |  B0   |  B1   |  B2   |  B3   |  B4   |  B5   |  B6   |  B7   |  B8   |  B9   |  B10  |  B11  |  B12  |  B13  |  B14  |  B15  |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **=>** | ***GUESS*** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |
|    | PUSH     | PUSH   | PUSH   | u   | t   | f   | l   | a   | g   | {   | 3   | c   | b   | _   | w   | 1   |
|    | 7     | h   | _   | r   | 4   | n   | d   | 0   | m   | _   | p   | r   | 3   | f   | 1   | x   |
| **=>** | **}** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |

When `GUESS` is equal to `}` then block 1 and block 4 are equal too.
Thanks to the weakness of ECB they will be encrypted in two equal blocks, revealing that a byte of the flag has been discovered.

Proceeding with the following bytes is quite simple.
Therefore, to guess the second byte, you have to make sure that server-side plaintext takes this form:

|   |  B0   |  B1   |  B2   |  B3   |  B4   |  B5   |  B6   |  B7   |  B8   |  B9   |  B10  |  B11  |  B12  |  B13  |  B14  |  B15  |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **=>** | ***GUESS*** | **}**     | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |
|  | PUSH        | PUSH  | PUSH  | PUSH  | u     | t     | f     | l     | a     | g     | {     | 3     | c     | b     | _     | w     |
|  | 1           | 7     | h     | _     | r     | 4     | n     | d     | 0     | m     | _     | p     | r     | 3     | f     | 1     |
| **=>** | **x**       | **}** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |

or, to guess the fifth byte:

|   |  B0   |  B1   |  B2   |  B3   |  B4   |  B5   |  B6   |  B7   |  B8   |  B9   |  B10  |  B11  |  B12  |  B13  |  B14  |  B15  |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **=>** | ***GUESS*** | **f** | **1** | **x** | **}** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |
|  | PUSH        | PUSH  | PUSH  | PUSH  | PUSH  | PUSH  | PUSH  | u     | t     | f     | l     | a     | g     | {     | 3     | c     |
|  | b           | _     | w     | 1     | 7     | h     | _     | r     | 4     | n     | d     | 0     | m     | _     | p     | r     |
| **=>** | **3**       | **f** | **1** | **x** | **}** | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* | *PAD* |


Here the code able to capture the whole flag:
```python
#! python3

from Crypto.Util.Padding import pad
import string
from pwn import remote, log

p = remote("ecb.utctf.live", 9003)

ATTEMPTS = 10
CHARS = string.printable[:-6]
CHARSX2 = [c1+c2 for c1 in CHARS for c2 in CHARS]
PRE_FLAG = "utflag{"
POST_FLAG = guessed = "}"
push = 2 + len(guessed)

def attempt(payload):
    p.recvline()
    p.sendline(payload)
    p.recvline()
    res = p.recvline()[:-1]
    return res[:16*2] == res[48*2:64*2]
    # NOTE: response is in hexadecimal format, two digits for each byte

def prepare_payload(guess):
    first_block = pad(guess.encode(), 16) if len(guess)<16 else guess[:16].encode()
    return first_block + push*b'P'

progress = log.progress('FLAG')
for pos in [i for i in range(len(guessed)+1, 24) if i!=7]:
    chars, push = (CHARS, push+1) if pos!=6 else (CHARSX2, push+2)
    for c in chars:
        progress.status(c+guessed)
        payload = prepare_payload(c+guessed)
        res = False
        for j in range(ATTEMPTS):
            if attempt(payload):
                res = True
                break
        if res:
            guessed = c+guessed
            break
    else:
        progress.failure(guessed)
        break

p.sendline("q")
progress.success(PRE_FLAG+guessed)
```

A problem encountered using this solution is that, according to PKCS #7 padding, pad bytes are equal to `\n` during sixth byte guessing.
This is a problem because on server-side `\n` characters are interpreted as a new-line, so, after the first of them, input acquisition is stopped.
As you can see in the code above, I have faced this problem making *2-bytes guessing* in that case.

#### Flag
```
$ ./exp.py
[+] FLAG: utflag{3cb_w17h_r4nd0m_pr3f1x}
```
