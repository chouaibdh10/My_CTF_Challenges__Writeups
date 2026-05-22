# Nextrace Challenge Writeup

Category: Forensics  
Date: 2025-10-24  
Tools: `exiftool`, `base64`, `steghide`

## Challenge Description

Given file: `can_u_see.jpg`  
Goal:

1. Inspect EXIF metadata
2. Decode a hidden Base64 value
3. Use recovered passphrase to extract hidden file

## Step-by-step

1. Inspect image metadata

```bash
exiftool can_u_see.jpg
```

Suspicious field:

```text
UserComment: cm91Z2k=
```

2. Decode Base64

```bash
echo "cm91Z2k=" | base64 -d
```

Output:

```text
rougi
```

3. Extract hidden file with `steghide`

```bash
steghide extract -sf can_u_see.jpg -p rougi
```

Expected:

```text
wrote extracted file "flag.txt"
```

4. Read flag

```bash
cat flag.txt
```

Output:

```text
nexus{chouaib_is_hereeeeeee}
```

## Flag

`nexus{chouaib_is_hereeeeeee}`
