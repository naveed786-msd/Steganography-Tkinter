# 🖼 Steganography Suite --- Text in Images

A Python GUI tool to **hide and extract secret text inside images**
using **LSB steganography**, with optional passphrase-based encryption.

------------------------------------------------------------------------

## ✨ Features

-   Hide text messages inside images.
-   Extract hidden text from stego images.
-   Optional passphrase to encrypt/decrypt hidden text.
-   Drag-and-drop support (with `tkinterdnd2` installed).
-   Preview images before embedding/extracting.
-   History log of actions (embed & extract).
-   Export history to CSV for record keeping.
-   Always saves output as **PNG** (lossless).

------------------------------------------------------------------------

## 📦 Requirements

-   Python 3.8+
-   [Pillow](https://pypi.org/project/Pillow/) --- `pip install pillow`
-   [tkinterdnd2](https://pypi.org/project/tkinterdnd2/) *(optional for
    drag & drop)* --- `pip install tkinterdnd2`

------------------------------------------------------------------------

## ▶️ Usage

1.  Clone or download this repository.

2.  Install dependencies:

    ``` bash
    pip install pillow
    pip install tkinterdnd2   # optional, enables drag & drop
    ```

3.  Run the app:

    ``` bash
    python Steganography_Tkinter.py
    ```

------------------------------------------------------------------------

## 🖥️ How It Works

-   **Embed Tab:**
    -   Select or drag an image.
    -   Enter your secret message.
    -   Optionally enter a passphrase (for encryption).
    -   Save the output image (PNG).
-   **Extract Tab:**
    -   Load or drag a stego image.
    -   Enter the passphrase if one was used.
    -   Click **Extract** to reveal the hidden text.
-   **History Tab:**
    -   View a list of all actions performed with timestamps.
    -   Export history log as CSV.

------------------------------------------------------------------------

## 🔒 Notes

-   Output images are always **PNG** to prevent compression from
    destroying hidden data.
-   If you use a passphrase, you must use the exact same passphrase to
    extract the message.
-   Large messages require larger images. If you exceed capacity, the
    app will notify you.

------------------------------------------------------------------------

## 📂 Project Structure

    SteganographyTool/
    │── Steganography_Tkinter.py   # Main application
    │── README.md                  # Project guide (this file)
    │── assets/                    # (optional) sample images/icons

------------------------------------------------------------------------

## 📸 Example

1.  Original image: `cat.png`
2.  Embed message: `"Hello World!"` with key `"secret123"`
3.  Save output as: `cat_stego.png`
4.  Use Extract tab + key `"secret123"` → reveals `"Hello World!"`

------------------------------------------------------------------------

## ⚖️ License

This project is released under the **MIT License** --- free to use,
modify, and distribute.

------------------------------------------------------------------------

Enjoy hiding your messages! 🔐

------------------------------------------------------------------------
##Developed by 
Shaik Naveed
