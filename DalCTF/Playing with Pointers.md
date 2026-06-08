# Playing with Pointers

Category: Reverse Engineering / C  
Difficulty: 500

## Challenge Description

The challenge provides a C program with one missing line:

```c
#include <stdio.h>

int main() {
    char FLAG[] = "DalCTF{test}";

    float fflag[sizeof(FLAG)];
    long lflag[sizeof(fflag)];
    int x = sizeof(FLAG);

    for (int i = 0; i < x; i++) {
        fflag[i] = (float) FLAG[i];
        fflag[i] = fflag[i] * fflag[i];
        // man I forgot what line needs to go here...
        // Maybe I should play some quake to think about it
    }

    x = x - 1;
    for (int i = 0; i < x; i++) {
        printf("\n%d", lflag[i]);
    }

    return 0;
}
```

The program converts each flag character to a float, squares it, then prints values from `lflag`.

## Analysis

The comment is the main hint:

```text
Maybe I should play some quake to think about it
```

This points to the famous Quake III Arena fast inverse square root trick, which reinterprets a floating-point value as an integer through a pointer cast:

```c
i = *(long *)&y;
```

So the missing line is likely:

```c
lflag[i] = *(long *)&fflag[i];
```

This does not numerically convert the float to an integer. It reads the raw IEEE-754 bytes of the float and interprets them as an integer.

## Output Values

The provided output contains the integer representations of each squared ASCII value:

```text
1167097856
1175651328
1177960448
1166821376
1172078592
1167663104
1181508608
1179558912
1158676480
1178182656
1159892992
1175258112
1176670208
1172424704
1178406912
1175258112
1180517376
1159073792
1161629696
1177092096
1175258112
1170735104
1158676480
1159073792
1178406912
1161629696
1159892992
1179324416
1160744960
1182016512
```

To recover the flag:

1. Pack each integer as raw bytes.
2. Unpack those bytes as a float.
3. Take the square root.
4. Convert the result back to an ASCII character.

## Solver

```python
import math
import struct

nums = [
    1167097856,
    1175651328,
    1177960448,
    1166821376,
    1172078592,
    1167663104,
    1181508608,
    1179558912,
    1158676480,
    1178182656,
    1159892992,
    1175258112,
    1176670208,
    1172424704,
    1178406912,
    1175258112,
    1180517376,
    1159073792,
    1161629696,
    1177092096,
    1175258112,
    1170735104,
    1158676480,
    1159073792,
    1178406912,
    1161629696,
    1159892992,
    1179324416,
    1160744960,
    1182016512,
]

flag = ""

for n in nums:
    f = struct.unpack("<f", struct.pack("<I", n))[0]
    flag += chr(round(math.sqrt(f)))

print(flag)
```

## Result

```text
DalCTF{s0m3_fUn_w17h_P01n73r5}
```

## Flag

`DalCTF{s0m3_fUn_w17h_P01n73r5}`

