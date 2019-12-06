# `subencode.py`

When producing binary exploits (e.g. buffer overflows), you often run into
restrictive environments which only permit certain bytes (e.g. alphanumeric).
One method to get around this is to "sub-encode" your data, and push it onto the
stack at runtime. For example, to push the value `0xDEADBEEF` onto the stack,
we could do the following uing only alphanumeric shellcode:

```asm
and eax,0x554e4d4a				# Zero out EAX
and eax,0x2a313235

sub eax,0x11292109				# 
sub eax,0x10292008
```

This shellcode assembles to the following: `%JMNU%521*-\t!)\x11-\x08 )\x10`. You
can easily see how this works in python:

```python
>>> (0-0x11292109) & 0xFFFFFFFF
4007059191
>>> (_-0x10292008) & 0xFFFFFFFF
3735928559
>>> hex(_)
'0xdeadbeef'
>>>
```

This script will automatically calculate the required sub-encoded bytes to
properly load the given data into memory in a restrictive environment. The
algorithm used here is derived from various articles, but as an example, a good
article can be read [here](https://marcosvalle.github.io/re/exploit/2018/10/05/sub-encoding.html).

## Usage

```
usage: subencode.py [-h] [--input INPUT] (--badbytes BADBYTES | --goodbytes GOODBYTES) [--max-div MAX_DIV]

Sub-encode the given data for use in exploits with restrictive bad bytes

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT, -i INPUT
                        File which contains the data to be encoded
  --badbytes BADBYTES, -b BADBYTES
                        A list of bad bytes. \x encodings are allowed.
  --goodbytes GOODBYTES, -g GOODBYTES
                        A list of allowed bytes. \x encodings are allowed
  --max-div MAX_DIV, -m MAX_DIV
                        Maximum number of divisions to find sub-encoding (default: 10)
```

## Example

```
$ ./subencode.py -g "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\
	\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\
	\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\
	\x37\x38\x39\x3b\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\
	\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\
	\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\
	\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f" < deadbeef.bin
chunks = [
    [0x11292109, 0x10292008],
]
```
