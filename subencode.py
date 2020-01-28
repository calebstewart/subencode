#!/usr/bin/env python3
from pwn import *
import argparse
import itertools
import resource
import sys
from io import BytesIO


class EncodingFailure(Exception):
    """ This is raised when a byte cannot be encoded automatically """

    pass


class DivisionFailed(Exception):
    """ This simply notifies encode_byte that check_div failed """

    pass


class BiggerDivision(Exception):
    """ This is raised when the located encoded has a larger value than the
    currently used encoding. It triggers encode_chunk to start over with a new
    minimum division size. """

    def __init__(self, div, *args, **kwargs):
        super(BiggerDivision, self).__init__(*args, **kwargs)
        self.div = div


def check_div(x, div, good_bytes, carry=0, recurse=False):
    """ Check if this division works. This will try to take the target value `x`
    and divide it into `div` sections which add up to `x` and are each themselves
    in the given `good_bytes` byte string.

    On success, this function returns a tuple of (carry_flag, value_array) where
    carry is set to true, if we had to increment `x` by 0x100, triggering a carry
    on the next byte.

    On failure, this function raises "DivisionFailed".
    """

    # Divide by the divisor
    v = x // div
    m = x % div

    # This is likely caused by a carry with a division that is too small
    if v >= 256:
        raise DivisionFailed

    # Easy, no modulos
    if mod == 0 and v in good_bytes:
        return carry, [v] * div

    if v in good_bytes:
        # Find all possible v modifications
        offsets = [c - v for c in good_bytes]

        # How many entries do we want to split this into?
        for split in range(1, div):
            # Iterate over all possibilities
            for offset_list in itertools.combinations_with_replacement(offsets, split):
                # Check if this works
                if sum(offset_list) == m:
                    return (
                        carry,
                        [v + offset for offset in offset_list] + [v] * (div - split),
                    )

    # If we've already carried, there's nothing we can do
    if recurse:
        raise DivisionFailed

    # Try to use the carry bit to our advantage
    return check_div(x + 0x100, div, good_bytes, carry=carry + 1, recurse=True)


def encode_byte(x, good_bytes, min_div=0, max_div=-1, carry=0):
    """ This function attempts to divide `x` into the minimum number of
    sub-encodings possible, starting at `min_div`.

    If `min_div` is zero, it will search from div=1 to div=max_div. If `min_div`
    is anything other than zero, it will start at `min_div`. If `min_div` does not
    work, but a higher div does, BiggerDivision is raised with the parameter being
    the correct division size.
    """

    # If min_div is uninitialized, we start at 2
    if min_div == 0:
        start_div = 1
    else:
        # Otherwise, start at the minimum division
        start_div = min_div

    # Loop up to the maximum division size
    for div in range(start_div, max_div & 0xFFFFFFFF):
        try:
            # Try to find valid values with this division
            carry, v = check_div(x, div, good_bytes, carry=carry)

            # This means that previous encodings are wrong (or at least contain
            # null bytes). It triggers encode_chunk to start over with this as
            # a new minimum division value.
            if min_div != 0 and div > min_div:
                raise BiggerDivision(div)

            # All good, return the value
            return carry, v
        except DivisionFailed:
            # check_div failed, that's fine. Continue looking for a good
            # division.
            continue
    else:
        # If we complete this loop, then we did not find any good divisions.
        # This script doesn't know how to encode this byte with the given
        # division restrictions :(
        raise EncodingFailure


def encode_chunk(chunk, good_bytes, initial, max_div=-1):
    """ Produce sub-encoding bytes for the given value. 
    """

    # Calculate a complement such that (0-X) & 0xFFFFFFFF = chunk
    X = (initial - chunk) & 0xFFFFFFFF

    # Initialize the encodings result, carry flag, and division size
    encodings = []
    carry = 0
    div = 0

    # We continue trying until we receive an EncodingFailure exception which is
    # passed back to the caller
    while True:

        try:
            # Iterate over each byte (least to most significant: important for
            # carry!)
            for i, x in enumerate(p32(X)):

                # Account for any carry from previous encoding
                # Also, account for natural carry if we wrap
                if x < carry:
                    x = (x - carry) & 0xFF
                    carry = 1
                else:
                    x = (x - carry) & 0xFF
                    carry = 0

                # Encode this byte
                carry, values = encode_byte(
                    x, good_bytes, min_div=div, max_div=max_div, carry=carry
                )

                # Initialize encodings matrix if this is the first result
                if div == 0:
                    div = len(values)
                    encodings = [[] for i in range(div)]

                # Add these values to the encoding matrix
                for i, v in enumerate(values):
                    encodings[i].append(v)
            else:
                # We successfully encoded all bytes! Now we can decode them
                # as integers and return!
                encodings_final = [u32(bytes(v)) for v in encodings]
                return encodings_final

        except BiggerDivision as e:
            # A single byte increased the size of our encodings.
            # Re-initialize the encodings and start over with a new minimum
            # division. This assumes that a null byte is a bad byte, but that's
            # pretty common...
            div = e.div
            encodings = [[] for i in range(div)]


def decode(encodings, initial):
    r = initial
    for v in encodings:
        r = (r - v) & 0xFFFFFFFF
    return r


def verify_chunk(chunk, encodings, initial):
    return chunk == decode(encodings, initial)


if __name__ == "__main__":

    # Build argument parser
    parser = argparse.ArgumentParser(
        description="Sub-encode the given data for use in exploits with restrictive bad bytes"
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--target", "-t", type=int, help="The target value for the register"
    )
    input_group.add_argument(
        "--input", "-i", default="-", help="File which contains the data to be encoded"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--badbytes", "-b", help="A list of bad bytes. \\x encodings are allowed."
    )
    group.add_argument(
        "--goodbytes", "-g", help="A list of allowed bytes. \\x encodings are allowed"
    )
    parser.add_argument(
        "--max-div",
        "-m",
        type=int,
        default=10,
        help="Maximum number of divisions to find sub-encoding (default: 10)",
    )
    parser.add_argument(
        "--initial",
        type=int,
        default=0,
        help="The initial value of the register you are filling (default: 0)",
    )
    args = parser.parse_args()

    # Grab good bytes list
    if args.goodbytes:
        good_bytes = bytes(args.goodbytes, "utf-8").decode("unicode_escape")
        good_bytes = bytes(good_bytes, "utf-8")
    else:
        bad_bytes = bytes(args.badbytes, "utf-8").decode("unicode_escape")
        good_bytes = bytes([c for c in range(256) if c not in bad_bytes])

    # Open and read data
    if args.target:
        data = BytesIO(p32(args.target))
    elif args.input == "-":
        data = sys.stdin.buffer
    else:
        data = open(args.input, "rb")

    chunks = []
    offset = 0

    while True:

        chunk = data.read(4)
        if chunk == b"" or chunk is None:
            break

        chunk = chunk.ljust(4, b"\x00")

        # Find the integer equivalent
        chunk = u32(chunk)

        try:
            encodings = encode_chunk(
                chunk, good_bytes, args.initial, max_div=args.max_div
            )
        except EncodingFailure:
            log.error(f"Failed to encode chunk at offset {offset:x}: {chunk:08x}")

        if not verify_chunk(chunk, encodings, args.initial):
            log.error(
                f"Chunk verification failed at offset {offset:x}: {chunk:08x}->{encodings}"
            )

        chunks.append(encodings)

    # Build output
    result = ["chunks = ["]
    for chunk in chunks:
        result.append(f"    {[hex(c) for c in chunk]},".replace("'", ""))
    result.append("]")
    result = "\n".join(result)

    # print it
    print(result)
