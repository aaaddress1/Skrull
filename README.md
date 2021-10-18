# Skrull

Skrull is a malware DRM, that prevents Automatic Sample Submission by AV/EDR and Signature Scanning from Kernel. It generates launchers that can run malware on the victim using the Process Ghosting technique. Also, launchers are totally anti-copy and naturally broken when got submitted.

It's a proof-of-concept of the talk of ROOTCON & HITCON 2021, check out *[Skrull Like A King: From File Unlink to Persistence](https://rootcon.org/html/rc15/talks#skull_like_a_king)* :)

**note that currently support only x64 PE now, due to the ghosting technique.**

## Video Demo
[![](https://img.youtube.com/vi/pRjRwl9tjXs/0.jpg)](https://www.youtube.com/watch?v=pRjRwl9tjXs)
