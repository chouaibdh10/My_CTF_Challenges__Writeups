
## 🕵️ Challenge Description

> Someone broke into our office last night, but they destroyed the hard drives with the security footage. Can you recover the footage?

We are given a `.pcap` file that contains HTTP traffic. Our goal is to extract and recover the images (security footage frames) from this capture.

---

## 🧰 Tools Used

* **Wireshark** — For analyzing HTTP packets and TCP streams.
* **Foremost** — For extracting image files based on file signatures.

---

## 🧾 Summary of Steps

### 1️⃣ Open the `.pcap` file in Wireshark

Make sure your terminal is in the same directory as the `.pcap` file.

```bash
wireshark security-footage.pcap
```

Wireshark displays all network packets — look for **HTTP traffic**.

---

### 2️⃣ Checking the TCP Stream

Once we inspect the TCP stream, we notice key indicators confirming the presence of image data.

**Steps:**

1. In Wireshark, right-click on any HTTP packet and choose:

   > **Follow → TCP Stream**
   > *(or use the shortcut `Ctrl + Alt + Shift + T`)*

2. You’ll see the full HTTP exchange — headers + content.

3. Look for headers such as:

   ```
   Content-Type: image/jpeg
   Content-Length: 20485
   ```

These headers confirm that the traffic contains **JPEG** images.


---

### 3️⃣ Applying a Filter for JPEG Traffic

To isolate relevant packets, apply the filter:

```bash
tcp contains "jpeg"
```

This filter looks for the ASCII string *jpeg* within TCP payloads — usually part of HTTP headers.
It’s a quick way to find all packets related to image transfers.

Multiple matches typically indicate **multiple images (frames)** are being transmitted.


---

### 4️⃣ Extracting Images Automatically with Foremost

Instead of manually saving each image, we can use **Foremost**, a forensic tool that identifies and extracts files based on header/footer signatures.

#### 🔹 Install Foremost

```bash
sudo apt install foremost
```

#### 🔹 Run Foremost on the `.pcap` file

```bash
foremost -i security-footage-1648933966395.pcap -o results_folder
```

Foremost scans the raw data and extracts all recognized files — in this case, JPEG images — into the `results_folder/`.


#### 🔹 Check the Output Folder

Inside `results_folder/jpg/`, you should find several images:

```bash
ls results_folder/jpg/
```


---

### 5️⃣ Viewing the Recovered Frames

Open the first image and **hold down the → (right arrow) key** on your keyboard.
This creates an **animated playback** effect, simulating the security footage.

---

## ✅ Result

You successfully recovered multiple JPEG frames from the `.pcap` file — effectively reconstructing the destroyed security footage.

---

## 🙏 Acknowledgments

Thanks to TryHackMe for this awesome forensic room!
And thanks for reading my writeup! 🚀
