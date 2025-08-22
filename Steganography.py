
import os
import struct
import hashlib
import time
from datetime import datetime
from typing import Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD  # type: ignore
    DND_AVAILABLE = True
except Exception:
    DND_AVAILABLE = False

from PIL import Image, ImageTk

MAGIC = b"STG1"  # 4 bytes identifying our payload
HEADER_FMT = ">4sB8sI"  # MAGIC, flags(1), keyhash(8), msg_len(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 17 bytes
FLAG_ENCRYPTED = 0b00000001


def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits):
    out = bytearray()
    acc = 0
    count = 0
    for b in bits:
        acc = (acc << 1) | (b & 1)
        count += 1
        if count == 8:
            out.append(acc)
            acc = 0
            count = 0
    if count != 0:  # pad remaining with zeros (shouldn't happen for our exact reads)
        out.append(acc << (8 - count))
    return bytes(out)


def _derive_keystream(key: str, nbytes: int) -> bytes:
    """Derive a pseudo-random keystream of length nbytes from a passphrase.
    Uses repeated SHA-256 expansions over key||counter.
    """
    key_bytes = key.encode("utf-8")
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        h = hashlib.sha256(key_bytes + counter.to_bytes(8, "big")).digest()
        out.extend(h)
        counter += 1
    return bytes(out[:nbytes])


def encrypt_message(msg: bytes, key: Optional[str]) -> Tuple[bytes, int, bytes]:
    """Return (ciphertext, flags, keyhash8). If key is None/empty, returns plaintext."""
    if key:
        keystream = _derive_keystream(key, len(msg))
        ct = bytes([m ^ k for m, k in zip(msg, keystream)])
        flags = FLAG_ENCRYPTED
        keyhash8 = hashlib.sha256(key.encode("utf-8")).digest()[:8]
        return ct, flags, keyhash8
    else:
        return msg, 0, b"\x00" * 8


def decrypt_message(ct: bytes, key: Optional[str], flags: int, keyhash8: bytes) -> bytes:
    if flags & FLAG_ENCRYPTED:
        if not key:
            raise ValueError("This message is encrypted. Passphrase required.")
        kh = hashlib.sha256(key.encode("utf-8")).digest()[:8]
        if kh != keyhash8:
            raise ValueError("Incorrect passphrase (hash mismatch).")
        keystream = _derive_keystream(key, len(ct))
        return bytes([c ^ k for c, k in zip(ct, keystream)])
    else:
        return ct


def calc_capacity_bits(img: Image.Image) -> int:
    # Use 3 color channels (ignore alpha)
    return img.width * img.height * 3


def embed_text_into_image(image_path: str, message: str, key: Optional[str], output_path: str) -> None:
    img = Image.open(image_path).convert("RGBA")
    base = img.convert("RGB")  # operate on RGB channels

    msg_bytes = message.encode("utf-8")
    payload, flags, keyhash8 = encrypt_message(msg_bytes, key)

    header = struct.pack(HEADER_FMT, MAGIC, flags, keyhash8, len(payload))
    full = header + payload

    bits_needed = len(full) * 8
    capacity = calc_capacity_bits(base)

    if bits_needed > capacity:
        raise ValueError(
            f"Message too large for this image. Need {bits_needed} bits, have {capacity} bits.\n"
            f"Tip: Use a larger image or shorten the message."
        )

    pixels = list(base.getdata())
    flat_channels = []
    for r, g, b in pixels:
        flat_channels.extend([r, g, b])

    bitgen = _bytes_to_bits(full)
    new_channels = []
    written = 0
    for ch in flat_channels:
        try:
            bit = next(bitgen)
            new_channels.append((ch & ~1) | bit)
            written += 1
        except StopIteration:
            new_channels.append(ch)

    # rebuild pixels
    it = iter(new_channels)
    new_pixels = [(next(it), next(it), next(it)) for _ in range(len(pixels))]

    stego_rgb = Image.new("RGB", base.size)
    stego_rgb.putdata(new_pixels)

    # restore alpha if any
    if img.mode == "RGBA":
        stego = Image.merge("RGBA", (*stego_rgb.split(), img.split()[3]))
    else:
        stego = stego_rgb

    # Save as PNG to avoid lossy compression
    if not output_path.lower().endswith(".png"):
        output_path += ".png"
    stego.save(output_path, format="PNG")


def extract_text_from_image(image_path: str, key: Optional[str]) -> str:
    img = Image.open(image_path).convert("RGB")

    pixels = list(img.getdata())
    flat_channels = []
    for r, g, b in pixels:
        flat_channels.extend([r, g, b])

    # First, read header bits -> HEADER_SIZE bytes
    header_bits = []
    for i in range(HEADER_SIZE * 8):
        header_bits.append(flat_channels[i] & 1)
    header_bytes = _bits_to_bytes(header_bits)

    try:
        magic, flags, keyhash8, msg_len = struct.unpack(HEADER_FMT, header_bytes)
    except struct.error:
        raise ValueError("No valid hidden data found (header malformed).")

    if magic != MAGIC:
        raise ValueError("No valid hidden data found (magic mismatch).")

    total_bits = (HEADER_SIZE + msg_len) * 8
    if total_bits > len(flat_channels):
        raise ValueError("Image does not contain full embedded payload (truncated).")

    # Read message bits right after header
    msg_bits = []
    start = HEADER_SIZE * 8
    for i in range(start, start + msg_len * 8):
        msg_bits.append(flat_channels[i] & 1)
    ct = _bits_to_bytes(msg_bits)

    pt = decrypt_message(ct, key, flags, keyhash8)
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        # If wrong key or not text
        raise ValueError("Failed to decode message as UTF-8 (wrong key or corrupted data).")


class StegoApp:
    def __init__(self):
        self.root = (TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk())
        self.root.title("Steganography Suite — Text in Images")
        self.root.geometry("980x680")
        self.root.configure(bg="#0f172a")
        self.history = []  # list of dicts
        self._build_ui()

    def _build_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="Steganography Suite",
            font=("Segoe UI", 22, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        )
        title.pack(pady=10)

        subtitle = tk.Label(
            self.root,
            text="Hide • Extract • Protect",
            font=("Segoe UI", 11),
            fg="#94a3b8",
            bg="#0f172a",
        )
        subtitle.pack()

        # Notebook
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", background="#0f172a")
        style.configure("TNotebook.Tab", background="#1e293b", foreground="white")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(expand=True, fill="both", padx=16, pady=12)

        self._build_embed_tab()
        self._build_extract_tab()
        self._build_history_tab()

    # ------------------ Embed Tab ------------------
    def _build_embed_tab(self):
        self.embed_tab = tk.Frame(self.nb, bg="#0b1220")
        self.nb.add(self.embed_tab, text="  Embed  ")

        left = tk.Frame(self.embed_tab, bg="#0b1220")
        left.pack(side="left", fill="both", expand=True, padx=12, pady=12)

        right = tk.Frame(self.embed_tab, bg="#0b1220")
        right.pack(side="right", fill="y", padx=12, pady=12)

        # Drop/Preview area
        self.embed_preview = tk.Label(
            left,
            text=(
                "Drop an image here\n(or click Browse)\n\nSupported: PNG, JPG. Output is PNG"
            ),
            bg="#111827",
            fg="#cbd5e1",
            bd=2,
            relief="groove",
            width=60,
            height=18,
            anchor="center",
            justify="center",
            font=("Segoe UI", 11),
        )
        self.embed_preview.pack(fill="both", expand=True)

        if DND_AVAILABLE:
            self.embed_preview.drop_target_register(DND_FILES)
            self.embed_preview.dnd_bind("<<Drop>>", self._on_embed_drop)

        btn_row = tk.Frame(left, bg="#0b1220")
        btn_row.pack(fill="x", pady=8)

        tk.Button(
            btn_row,
            text="Browse Image…",
            command=lambda: self._choose_image(for_embed=True),
            bg="#1f2937",
            fg="white",
            padx=12,
            pady=6,
        ).pack(side="left")

        # Message + key
        tk.Label(right, text="Secret Message", bg="#0b1220", fg="#e5e7eb", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.embed_message = tk.Text(right, height=12, wrap="word", bg="#111827", fg="#e5e7eb")
        self.embed_message.pack(fill="y", pady=6)

        tk.Label(right, text="Passphrase (optional)", bg="#0b1220", fg="#e5e7eb").pack(anchor="w", pady=(8, 0))
        self.embed_key = tk.Entry(right, show="*", bg="#111827", fg="#e5e7eb")
        self.embed_key.pack(fill="x")

        self.embed_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            right,
            text="Show",
            variable=self.embed_show_var,
            command=lambda: self.embed_key.config(show="" if self.embed_show_var.get() else "*"),
            bg="#0b1220",
            fg="#e5e7eb",
            selectcolor="#111827",
        ).pack(anchor="w")

        self.embed_path: Optional[str] = None

        action = tk.Frame(right, bg="#0b1220")
        action.pack(fill="x", pady=10)
        tk.Button(
            action,
            text="Hide & Save",
            command=self._do_embed,
            bg="#059669",
            fg="white",
            padx=16,
            pady=10,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

    def _on_embed_drop(self, event):
        path = event.data
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        if os.path.isfile(path):
            self._set_embed_image(path)

    def _choose_image(self, for_embed=False, for_extract=False):
        path = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.tif;*.tiff"), ("All files", "*.*")],
        )
        if not path:
            return
        if for_embed:
            self._set_embed_image(path)
        if for_extract:
            self._set_extract_image(path)

    def _set_embed_image(self, path: str):
        try:
            img = Image.open(path)
            preview = img.copy()
            preview.thumbnail((720, 420))
            self._embed_imgtk = ImageTk.PhotoImage(preview)
            self.embed_preview.configure(image=self._embed_imgtk, text="")
            self.embed_path = path
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")

    def _do_embed(self):
        if not self.embed_path:
            messagebox.showwarning("No image", "Please choose an image to embed into.")
            return
        message = self.embed_message.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("No message", "Please enter a secret message to embed.")
            return
        key = self.embed_key.get().strip() or None
        default_name = os.path.splitext(os.path.basename(self.embed_path))[0] + "_stego.png"
        out_path = filedialog.asksaveasfilename(
            title="Save stego image",
            defaultextension=".png",
            initialfile=default_name,
            filetypes=[("PNG Image", "*.png")],
        )
        if not out_path:
            return
        try:
            start = time.time()
            embed_text_into_image(self.embed_path, message, key, out_path)
            elapsed = time.time() - start
            messagebox.showinfo("Success", f"Hidden message saved to:\n{out_path}\n\nTime: {elapsed:.2f}s")
            self._log_history("Embed", self.embed_path, out_path, len(message))
        except Exception as e:
            messagebox.showerror("Embed failed", str(e))

    # ------------------ Extract Tab ------------------
    def _build_extract_tab(self):
        self.extract_tab = tk.Frame(self.nb, bg="#0b1220")
        self.nb.add(self.extract_tab, text="  Extract  ")

        left = tk.Frame(self.extract_tab, bg="#0b1220")
        left.pack(side="left", fill="both", expand=True, padx=12, pady=12)

        right = tk.Frame(self.extract_tab, bg="#0b1220")
        right.pack(side="right", fill="y", padx=12, pady=12)

        self.extract_preview = tk.Label(
            left,
            text="Drop an image with hidden text here\n(or click Browse)",
            bg="#111827",
            fg="#cbd5e1",
            bd=2,
            relief="groove",
            width=60,
            height=18,
            anchor="center",
            justify="center",
            font=("Segoe UI", 11),
        )
        self.extract_preview.pack(fill="both", expand=True)

        if DND_AVAILABLE:
            self.extract_preview.drop_target_register(DND_FILES)
            self.extract_preview.dnd_bind("<<Drop>>", self._on_extract_drop)

        btn_row = tk.Frame(left, bg="#0b1220")
        btn_row.pack(fill="x", pady=8)
        tk.Button(
            btn_row,
            text="Browse Image…",
            command=lambda: self._choose_image(for_extract=True),
            bg="#1f2937",
            fg="white",
            padx=12,
            pady=6,
        ).pack(side="left")

        tk.Label(right, text="Passphrase (if used)", bg="#0b1220", fg="#e5e7eb").pack(anchor="w", pady=(8, 0))
        self.extract_key = tk.Entry(right, show="*", bg="#111827", fg="#e5e7eb")
        self.extract_key.pack(fill="x")
        self.extract_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            right,
            text="Show",
            variable=self.extract_show_var,
            command=lambda: self.extract_key.config(show="" if self.extract_show_var.get() else "*"),
            bg="#0b1220",
            fg="#e5e7eb",
            selectcolor="#111827",
        ).pack(anchor="w")

        tk.Label(right, text="Extracted Message", bg="#0b1220", fg="#e5e7eb", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 0))
        self.extract_output = tk.Text(right, height=12, wrap="word", bg="#111827", fg="#e5e7eb")
        self.extract_output.pack(fill="y", pady=6)

        self.extract_path: Optional[str] = None

        action = tk.Frame(right, bg="#0b1220")
        action.pack(fill="x", pady=10)
        tk.Button(
            action,
            text="Extract",
            command=self._do_extract,
            bg="#2563eb",
            fg="white",
            padx=16,
            pady=10,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left")

    def _on_extract_drop(self, event):
        path = event.data
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        if os.path.isfile(path):
            self._set_extract_image(path)

    def _set_extract_image(self, path: str):
        try:
            img = Image.open(path)
            preview = img.copy()
            preview.thumbnail((720, 420))
            self._extract_imgtk = ImageTk.PhotoImage(preview)
            self.extract_preview.configure(image=self._extract_imgtk, text="")
            self.extract_path = path
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {e}")

    def _do_extract(self):
        if not self.extract_path:
            messagebox.showwarning("No image", "Please choose an image to extract from.")
            return
        key = self.extract_key.get().strip() or None
        try:
            start = time.time()
            msg = extract_text_from_image(self.extract_path, key)
            elapsed = time.time() - start
            self.extract_output.delete("1.0", "end")
            self.extract_output.insert("1.0", msg)
            messagebox.showinfo("Done", f"Message extracted in {elapsed:.2f}s")
            self._log_history("Extract", self.extract_path, None, len(msg))
        except Exception as e:
            messagebox.showerror("Extract failed", str(e))

    # ------------------ History Tab ------------------
    def _build_history_tab(self):
        self.history_tab = tk.Frame(self.nb, bg="#0b1220")
        self.nb.add(self.history_tab, text="  History  ")

        cols = ("time", "action", "source", "output", "length")
        self.tree = ttk.Treeview(self.history_tab, columns=cols, show="headings")
        for c, w in zip(cols, (180, 80, 260, 260, 80)):
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=12, pady=12)

        btns = tk.Frame(self.history_tab, bg="#0b1220")
        btns.pack(fill="x", padx=12, pady=(0, 12))
        tk.Button(btns, text="Export Log…", command=self._export_history, bg="#1f2937", fg="white").pack(side="left")
        tk.Button(btns, text="Clear", command=self._clear_history, bg="#7f1d1d", fg="white").pack(side="left", padx=8)

    def _log_history(self, action: str, src: Optional[str], out: Optional[str], msg_len: int):
        record = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "source": src or "-",
            "output": out or "-",
            "length": msg_len,
        }
        self.history.append(record)
        self.tree.insert("", "end", values=(record["time"], action, record["source"], record["output"], msg_len))

    def _export_history(self):
        if not self.history:
            messagebox.showinfo("No data", "History is empty.")
            return
        path = filedialog.asksaveasfilename(
            title="Save history log",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="stego_history.csv",
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["time", "action", "source", "output", "length"])
                writer.writeheader()
                writer.writerows(self.history)
            messagebox.showinfo("Saved", f"History exported to\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _clear_history(self):
        self.history.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)

    def run(self):
        # Note when drag & drop is not active
        if not DND_AVAILABLE:
            note = tk.Label(
                self.root,
                text="Drag & drop disabled (install tkinterdnd2 to enable)",
                bg="#0f172a",
                fg="#fbbf24",
                font=("Segoe UI", 9),
            )
            note.pack(pady=(0, 6))
        self.root.mainloop()


if __name__ == "__main__":
    app = StegoApp()
    app.run()
