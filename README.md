# Page‑Phantoms  
A Dual‑Layer Defense and Attack Demonstration Framework for PageCache Manipulation, MGLRU Abuse, and Zero‑I/O Phantom Attack Research

This repository accompanies my **BHEU presentation**, documented in  
`eu-25-JIA-Page-Phantoms-Zero-IO-White-Paper.pdf`,  
which explains the theoretical background and full attack/defense model.

The project contains **In‑Guest monitoring modules**, **Host‑side VMM integrity enforcement**, and **MGLRU‑based attack demonstration tools**.  
It is designed for research on *phantom pages*, *GPA shadowing*, *pagecache manipulation*, and *zero‑I/O integrity attacks*.

---

## Repository Structure

```
page-phantoms/
├── eu-25-JIA-Page-Phantoms-Zero-IO-White-Paper.pdf  ← BHEU Whitepaper
├── host-vmm/
│   └── vm-detect/            ← Host‑side integrity monitor
└── in-guest/
    ├── filemon/              ← PageCache + I/O monitor (kernel module)
    ├── getinode/             ← Inode metadata extractor + GPA sender
    ├── mglru-deceit/         ← MGLRU attacker modules + mglru-ctl tool
    └── pc-watch.py           ← Optional user‑space monitoring helper
```

---

## Overview

Page‑Phantoms demonstrates a **two‑layer defense model** and a **multi‑stage attack chain** involving:

* PageCache access tracking  
* MGLRU behavior manipulation  
* GPA‑based metadata hijacking  
* Zero‑I/O phantom page attacks  
* Host‑Guest cooperative integrity verification  

The workflow is designed to show both **defensive** and **offensive** capabilities.

---

# 1. In‑Guest Components

## 1.1 Compile and Load `filemon.ko`  
This module hooks PageCache and I/O paths and provides real‑time monitoring of:

* page aging  
* file‑to‑page relations  
* pagecache accesses  
* disk I/O behavior  

Compile:

```
cd in-guest/filemon
make
sudo insmod filemon.ko
```

---

## 1.2 Compile and Load `getinode.ko`  
This module extracts detailed inode metadata of target files inside the Guest OS.

```
cd in-guest/getinode
make
sudo insmod getinode.ko
```

Then run the GPA sender:

```
./gpa_sender <path/to/target/file>
```

This sends the target file’s **GPA** and **metadata** to the Host‑VMM monitor.

---

# 2. Host‑VMM Component

## 2.1 Build and Run `vm-detect`
The Host monitor computes **metadata integrity hashes** (SHA‑256) of the pages received from the Guest.

```
cd host-vmm/vm-detect
make
sudo ./vm-detect
```

This establishes **Layer 2 defense**, ensuring that even if Guest memory mappings are altered, the Host detects metadata inconsistencies.

---

# 3. Combined Defense Model

When both sides are active:

1. **Guest Layer 1**  
   *filemon + getinode*  
   Monitor PageCache & inode metadata in the Guest.

2. **Host Layer 2**  
   *vm-detect*  
   Computes metadata hashes to detect tampering, phantom pages, or MGLRU‑induced anomalies.

Together they form a **dual‑layer integrity monitoring system** against zero‑I/O pagecache tampering.

---

# 4. Attack Demonstration Tools

## 4.1 Compile and Load `mglru-deceit.ko`
This kernel module exploits MGLRU behavior to create phantom pages and manipulate aging.

```
cd in-guest/mglru-deceit
make
sudo insmod mglru-deceit.ko
```

---

## 4.2 Use the `mglru-ctl` User Tool

```
./mglru-ctl --dump-mglru
```

Options:

* `--dump-mglru`  
  Dump and display all MGLRU file pages.

* `--phantom-page <sub-option>`  
  Instantly find and map a target page (phantom-style).

* `--listen-phantom <sub-option>`  
  Actively monitor and modify a target page.

Sub‑options:

* `-clrpass`  
  Clear root password via *phantom page 0*.

* `-chgpass`  
  Set root password to `"123"` via *phantom page 1*.

These tools reproduce the **Zero‑I/O Phantom Page Attack** shown in the BHEU talk.

---

# 5. Whitepaper  
The file:

```
eu-25-JIA-Page-Phantoms-Zero-IO-White-Paper.pdf
```

is my **BHEU presentation document**, containing:

* Phantom Page architecture  
* Zero‑I/O attack methods  
* MGLRU exploitation  
* Defense rationale and model  
* Experiment results  

This repository implements everything described in the whitepaper.

---

# 6. Build Requirements

Guest:

* gcc / clang  
* kernel headers  
* make  
* root privileges for module loading  

Host‑VMM:

* gcc  
* OpenSSL (`libssl-dev`)  
* Linux KVM/QEMU (optional)

Install missing dependency:

```
sudo apt install libssl-dev
```

---

# 7. License and Notes

This repository is intended only for:

* academic research  
* security analysis  
* operating system study  

Do not deploy in production or hostile environments.

---
