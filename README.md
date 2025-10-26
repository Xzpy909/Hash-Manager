# 📂 Hash Manager

A simple, multi-threaded GUI application built with Python and Tkinter for **generating** and **verifying** file integrity using high-speed **xxHash** or the more secure **SHA256** algorithms.

This tool is useful for ensuring the integrity of files within a directory, detecting accidental corruption, or verifying backups.

## ✨ Features

* **Algorithm Choice:** Select between two popular hashing algorithms:
    * **xxHash (`xxh64`):** Extremely fast, ideal for quick integrity checks.
    * **SHA256 (`sha256`):** More secure, standard for cryptographic verification.
* **Checksum Storage:** Generates a `checksums.xxhash` or `checksums.sha256` file in the target directory.
* **Multi-threaded:** Hashing and verification operations run in a background thread, preventing the GUI from freezing.
* **Relative Path Tracking:** Stores hashes using relative paths, making the checksum file portable.
* **Verification Report:** Clearly identifies **corrupted**, **missing**, and **new** files found during verification.
* **GUI:** Intuitive graphical interface for selecting a directory and performing operations.

## 🛠️ Requirements

The application requires Python 3 and the following external libraries:

* `xxhash`
* `Pillow` (if you were to add an icon, though currently not strictly required)

You can install the necessary dependencies using pip:

```bash
pip install xxhash
