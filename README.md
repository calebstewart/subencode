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

## Algorithm/Methodology

The basic idea behind sub-encoding is normally centered around the idea that
your input is restricted to "alphanumeric" characters or some subset thereof. We
assume we are allowed to use the instructions `sub` and `and`. These
instructions assemble to the values "-" and "%" respectively. These are normally
allowed characters. You can read up on how to zero a register with two `and`
instructions elsewhere, but just believe me that it is possible.

Next, we want to use the subtract instruction, and a property of bounded integer
math. Basically, if a 32-bit number is subtract such that it would be negative,
it "wraps" around:

```python
>>> 0 - 5
-5
>>> hex(_ & 0xFFFFFFFF)
'0xfffffffb'
>>> hex(2**32 - 5)
'0xfffffffb'
```

Great! So, theoretically, if we continue subtracting allowed bytes, we can wrap
around back to the original thing we wanted that wasn't allowed. We have to
select these individual bytes such that they are within the allowed (or "good")
bytes.

First, let's call the thing we want `goal`. We will use `goal=0xdeadbeef`
as an example. Next, we need to calculate a number which when subtracted from
zero will equal `goal`. We'll call this number `X`. We can do this in python
fairly easily:

```python
>>> goal = 0xdeadbeef
>>> X = ((0xFFFFFFFF+1) - goal) & 0xFFFFFFFF
>>> hex(X)
'0x21524111'
>>> hex((0 - X) & 0xFFFFFFFF)
'0xdeadbeef'
```

Great, now we need to find some set of numbers which when added to gether equal
`X`. We will use 3 numbers as an example. We'll call the three numbers `a`, `b`,
and `c`. We are trying to solve this:

```
X = a + b + c
# so that...
0 - X = 0 - a - b - c = goal
```

The idea here is that if any of the bytes in `X` are outside the range of our
"good" bytes, then we will likely end up within range by dividing them by 3.
This is often true with alphanumeric restrictions. We can find these numbers by
hand one byte at a time. We start with the least significant byte, and work
upwards so we can account for any "carry". For example, the first byte (good
bytes = 0x00-0x7f):

```python
X1 = 0x11
X1 / 3 = 5.66666667
X1 % 3 = 2

a1 = 0x6
b1 = 0x6
c1 = 0x5
a1 + b1 + c1 = 0x11
```

The idea is that if the value divided by three is within our good bytes, we can
use that as the value of `a1`, `b1`, `c1`. If there is a modulos (like above),
then we have to add or subtract one from one or more of the bytes to max the
equation `a+b+c=X` remain true, while again checking our good bytes list.

## Abstracting the Methodology

To implement the above methodology, I wanted to use an arbitrary divisor, such
that you could encode a single 32-bit value into 1, 2, 3 or even higher numbers
of subtractions. This allows the algorithm to calculate sub-encodings for even
more restrictive shellcode environments. 

I started by creating a function `encode_chunk`. This function does the
following:

1. Calculates X for the 32-bit chunk
2. Iterates over the bytes in X
	- Attempts to encode this byte
	- If the number of divisions is unitialized, it saves the division count as
	  a minimum and continues to the next byte.
	- If the number of divisions is greater than previous encodings, it restarts
	  the entire process with this new count as the minimum.
	- It also accounts for failed encodings by catching a special exception
	  type.
	- Division mismatches are also accounted for with a special exception.
3. Compiles the individual components of `[a, b, c, ...]` into 32-bit integers
   and returns them.

In order to encode a single byte, I created a function called `encode_byte`
which does the following:

1. Iterates over all possible divisions, starting at 1 if no minimum division is
   specified, or starting at `min_div` if specified.
2. Checks if this division works for the given byte, and retrieves the `[a, b,
   c, ...]` bytes for it.
3. If the division is correct, but is larger than `min_div` and `min_div` was
   specified, raise our custom Division mismatch exception, specifying the new
   minimum division.
3. If the division is correct, and is the same as `min_div`, then return the
   carry state, and the `[a, b, c, ...]` values.
4. If all division options (bounded by a command line parameter) are exhausted,
   raise an EncodingFailure exception, signifying we don't know how to encode
   this chunk.

`encode_byte` utilizes the `check_div` function to check if a given division
produces valid results. It does this by:

1. Dividing the byte by the given division.
2. Finding the modulos.
3. If modulos is zero and the divided value is in the good bytes, return the
   value `div` times (e.g. `sum([x/div]*div)=x`.
4. If modulos is non-zero and the divided value is in good bytes, we could
   distribute the modulos in a very large number of ways. I define this as a
   `split`, AKA the number of values to modify, while keeping the rest with the
   divided value.
	- I iterate over all combinations of good bytes for a given split value, and
	  find one that sums to the modulos. This is essentially
	  `sum([y0,y1,...ysplit]+[x//div]*(div-split))=x`.
5. If no combinations are found or `x//div` is not in the good bytes, we carry
   by adding 0x100 to the current byte, and subtracting 1 from the next byte,
   and redo the same operation. We only allow one carry operation (on recursion)
   before signalling that this division failed.

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

## Extreme Example

Here is an extreme example with an incredibly restricted character set. The
encoding mechanism finds the smallest size of encoding. With a small
character set, the length of each encoding gross:

```
$ dd if=/dev/urandom bs=1 count=350 of=./test
$ ./subencode.py -g "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39" < test
chunks = [
    [0x1224042d, 0xf23032a, 0xf23032a, 0xf23032a],
    [0xb213406, 0x91e3006, 0x91e3006, 0x91e3006, 0x91e3006],
    [0x52c270d, 0x428260b, 0x428260b, 0x428260b, 0x428260b, 0x428260b],
    [0x29381037, 0x28351036, 0x28351036, 0x28351036],
    [0x17390808, 0x14370706, 0x14370706, 0x14370706],
    [0x2d253531, 0x2213331, 0x17213331, 0x17213331, 0x17213331],
    [0x10092627, 0xf072426, 0xf072426, 0xf072426, 0xf072426],
    [0x361f1b03, 0x32041902, 0x32101902, 0x32101902, 0x32101902],
    [0x2a071c36, 0x28041a36, 0x28041a36, 0x28041a36],
    [0x2a260e03, 0x28260e03, 0x28260e03, 0x28260e03, 0x28260e02],
    [0x2a362619, 0x2a362419, 0x2a362419, 0x2a362419],
    [0x1b2b2b13, 0x1b2b2712, 0x1b2b2712, 0x1b2b2712, 0x1b2b2712, 0x1b2b2712],
	...
    [0x22270813, 0x1e240612, 0x1e240612, 0x1e240612, 0x1e240612],
    [0x20242d34, 0x1e230231, 0x1e231731, 0x1e231731],
    [0x31121227, 0x31121125, 0x31121125, 0x31121125],
    [0x3c1f2c26, 0x2b1e2822, 0x321e2822, 0x321e2822, 0x321e2822],
    [0x33173035, 0x33142e35, 0x33142e35, 0x33142e35],
    [0x2d183510, 0x2b153310, 0x2b153310, 0x2b153310, 0x2b153310],
    [0x9070924, 0x6050723, 0x6050723, 0x6050723],
    [0x20121f34, 0x1f101f31, 0x1f101f31, 0x1f101f31],
    [0x18031934, 0x14021833, 0x14021833, 0x14021833, 0x14021833],
    [0x37272b1e, 0x34232a1d, 0x34232a1d, 0x34232a1d, 0x34232a1d],
    [0x30222f05, 0x2e202b04, 0x2e202b03, 0x2e202b03, 0x2e202b03],
    [0x37250b0a, 0x34220909, 0x34220909, 0x34220909],
    [0x2322090f, 0x61f060f, 0x121f060f, 0x121f060f, 0x121f060f, 0x121f060f],
    [0x18233405, 0x15223203, 0x15223203, 0x15223203, 0x15223203],
    [0x33331b02, 0x33330502, 0x33330e02, 0x33330e02, 0x33330e02],
]
```
