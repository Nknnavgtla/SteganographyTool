# --- Standard Library ---
import os
import io
import zlib
import struct
import sys
import math
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

# --- Pillow (Image processing) ---
from PIL import Image  # ✅ use Pillow, not 'import PIL'

# --- Optional tkinterdnd2 import for drag-and-drop ---
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    TKDND_AVAILABLE = True
except ImportError:
    TKDND_AVAILABLE = False

# --- Tkinter (GUI) ---
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- Crypto (AES-256-GCM with PBKDF2 key derivation) ---
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


MAGIC = b"STG1"  # 4 bytes
VERSION = 1       # 1 byte

# flags bitfield
FLAG_ENCRYPTED = 1 << 0  # 0x01
FLAG_IS_FILE   = 1 << 1  # 0x02  (else text)

HEADER_FMT = ">4sBBBH I"  # magic, version, flags, name_len(2), salt_len(1), payload_len(4)
# Explanation: > big-endian; 4s, B, B, B(?), H(2), I(4) -> we need name_len as H (2 bytes), salt_len as B (1 byte)
# Correct layout: magic(4s), version(B), flags(B), name_len(H), salt_len(B), payload_len(I)
HEADER_FMT = ">4sBBHBI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 12

SUPPORTED_FORMATS = {"PNG", "BMP"}

@dataclass
class EmbeddingPlan:
    capacity_bits: int
    capacity_bytes: int
    needed_bytes: int
    fits: bool


def img_capacity_bytes(img: Image.Image) -> int:
    # 1 LSB per channel, 3 channels
    w, h = img.size
    bits = w * h * 3
    return bits // 8


def check_image_mode(img: Image.Image) -> Image.Image:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA") if "A" in img.getbands() else img.convert("RGB")
    return img


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_if_needed(data: bytes, passphrase: Optional[str]) -> Tuple[bytes, bytes, bytes]:
    """Return (ciphertext_or_plain, salt, nonce_or_empty)."""
    if passphrase:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Encryption requested but 'cryptography' is not installed.")
        salt = secrets.token_bytes(SALT_LEN)
        key = derive_key(passphrase, salt)
        aes = AESGCM(key)
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = aes.encrypt(nonce, data, associated_data=None)
        return ct, salt, nonce
    else:
        return data, b"", b""


def decrypt_if_needed(data: bytes, passphrase: Optional[str], salt: bytes, nonce: bytes) -> bytes:
    if salt and passphrase:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Decryption requested but 'cryptography' is not installed.")
        key = derive_key(passphrase, salt)
        aes = AESGCM(key)
        return aes.decrypt(nonce, data, associated_data=None)
    return data


def build_header(flags: int, name: str, salt_len: int, payload_len: int) -> bytes:
    name_bytes = name.encode("utf-8") if name else b""
    return struct.pack(HEADER_FMT, MAGIC, VERSION, flags, len(name_bytes), salt_len, payload_len) + name_bytes


def parse_header(buf: bytes) -> Tuple[int, int, int, int, int, str, int]:
    if len(buf) < HEADER_SIZE:
        raise ValueError("Carrier image does not contain a valid Stego header.")
    magic, ver, flags, name_len, salt_len, payload_len = struct.unpack(HEADER_FMT, buf[:HEADER_SIZE])
    if magic != MAGIC:
        raise ValueError("Magic header not found. This image likely has no embedded data.")
    if ver != VERSION:
        raise ValueError(f"Unsupported version {ver}.")
    offset = HEADER_SIZE
    name = buf[offset:offset + name_len].decode("utf-8", errors="replace") if name_len else ""
    offset += name_len
    return ver, flags, name_len, salt_len, payload_len, name, offset


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    by = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            if i + j < len(bits):
                b = (b << 1) | (bits[i + j] & 1)
            else:
                b <<= 1
        by.append(b)
    return bytes(by)


def embed_bits_in_image(img: Image.Image, bits: list[int]) -> Image.Image:
    img = check_image_mode(img)
    pixels = img.load()
    w, h = img.size
    idx = 0
    for y in range(h):
        for x in range(w):
            if img.mode == "RGB":
                r, g, b = pixels[x, y]
                if idx < len(bits): r = (r & ~1) | bits[idx]; idx += 1
                if idx < len(bits): g = (g & ~1) | bits[idx]; idx += 1
                if idx < len(bits): b = (b & ~1) | bits[idx]; idx += 1
                pixels[x, y] = (r, g, b)
            else:  # RGBA
                r, g, b, a = pixels[x, y]
                if idx < len(bits): r = (r & ~1) | bits[idx]; idx += 1
                if idx < len(bits): g = (g & ~1) | bits[idx]; idx += 1
                if idx < len(bits): b = (b & ~1) | bits[idx]; idx += 1
                pixels[x, y] = (r, g, b, a)
            if idx >= len(bits):
                return img
    if idx < len(bits):
        raise ValueError("Not enough pixels to embed payload.")
    return img


def extract_bits_from_image(img: Image.Image, num_bits: int) -> list[int]:
    img = check_image_mode(img)
    pixels = img.load()
    w, h = img.size
    bits = []
    for y in range(h):
        for x in range(w):
            if img.mode == "RGB":
                r, g, b = pixels[x, y]
                bits.append(r & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
                bits.append(g & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
                bits.append(b & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
            else:
                r, g, b, a = pixels[x, y]
                bits.append(r & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
                bits.append(g & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
                bits.append(b & 1)
                if len(bits) >= num_bits: return bits[:num_bits]
    return bits[:num_bits]


# --- High-level API ---

def plan_embedding(img_path: str, payload_len: int, name: str, will_encrypt: bool) -> EmbeddingPlan:
    with Image.open(img_path) as im:
        im = check_image_mode(im)
        cap = img_capacity_bytes(im)
    # header size dynamic (name + salt + nonce)
    salt_len = SALT_LEN if will_encrypt else 0
    nonce_len = NONCE_LEN if will_encrypt else 0
    flags = (FLAG_ENCRYPTED if will_encrypt else 0) | (FLAG_IS_FILE if name else 0)
    header_len = HEADER_SIZE + len(name.encode("utf-8")) + salt_len + nonce_len
    needed = header_len + payload_len
    return EmbeddingPlan(capacity_bits=cap*8, capacity_bytes=cap, needed_bytes=needed, fits=needed <= cap)


def embed(img_path: str, out_path: str, data: bytes, name: str, passphrase: Optional[str]) -> None:
    # Compress payload first
    compressed = zlib.compress(data, level=9)
    ct, salt, nonce = encrypt_if_needed(compressed, passphrase)

    flags = 0
    if passphrase:
        flags |= FLAG_ENCRYPTED
    if name:
        flags |= FLAG_IS_FILE

    header = build_header(flags, name, len(salt) + len(nonce), len(ct))
    full = header + salt + nonce + ct

    with Image.open(img_path) as im:
        im = check_image_mode(im)
        cap = img_capacity_bytes(im)
        if len(full) > cap:
            raise ValueError(f"Payload too large. Need {len(full)} bytes, image can hold {cap} bytes.")
        bits = bytes_to_bits(full)
        stego = embed_bits_in_image(im, bits)
        ext = os.path.splitext(out_path)[1].lower()
        fmt = "PNG" if ext == ".png" else "BMP" if ext == ".bmp" else None
        if fmt is None:
            fmt = "PNG"
            out_path = os.path.splitext(out_path)[0] + ".png"
        stego.save(out_path, format=fmt)


def extract(img_path: str, passphrase: Optional[str]) -> Tuple[bytes, bool, str]:
    with Image.open(img_path) as im:
        im = check_image_mode(im)
        cap_bytes = img_capacity_bytes(im)
        # First, read enough bits to parse header and a reasonable name
        header_guess_bytes = HEADER_SIZE + 256  # header + up to 256 name bytes
        bits = extract_bits_from_image(im, header_guess_bytes * 8)
        head_plus = bits_to_bytes(bits)
        # Parse fixed header
        if len(head_plus) < HEADER_SIZE:
            raise ValueError("Image too small to contain header.")
        magic = head_plus[:4]
        if magic != MAGIC:
            raise ValueError("Magic header not found. Not a StegoBox image.")
        _, flags, name_len, salt_len, payload_len, name, offset = parse_header(head_plus)
        need_first = offset + salt_len
        if len(head_plus) < need_first:
            # Read more to include salt/nonce and ensure header complete
            extra_needed = need_first - len(head_plus)
            extra_bits = extract_bits_from_image(im, (len(head_plus) + extra_needed) * 8)
            head_plus = bits_to_bytes(extra_bits)
        # Now total bytes to read = offset + salt_len + payload_len
        total_bytes = offset + salt_len + payload_len
        if total_bytes > cap_bytes:
            raise ValueError("Declared payload exceeds image capacity; image may be corrupted.")
        bits = extract_bits_from_image(im, total_bytes * 8)
        all_bytes = bits_to_bytes(bits)
        # Re-parse
        _, flags, name_len, salt_len, payload_len, name, offset = parse_header(all_bytes)
        salt_nonce = all_bytes[offset:offset + salt_len]
        offset += salt_len
        payload = all_bytes[offset:offset + payload_len]
        enc = bool(flags & FLAG_ENCRYPTED)
        is_file = bool(flags & FLAG_IS_FILE)
        salt = b""
        nonce = b""
        if enc:
            salt = salt_nonce[:SALT_LEN]
            nonce = salt_nonce[SALT_LEN:SALT_LEN + NONCE_LEN]
        # Decrypt → decompress
        plain = decrypt_if_needed(payload, passphrase if enc else None, salt, nonce)
        try:
            plain = zlib.decompress(plain)
        except zlib.error:
            raise ValueError("Decompression failed. Wrong password or corrupted data.")
        return plain, is_file, name


# --- Tkinter GUI ---
class StegoBoxApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("StegoBox — Image/File Steganography (LSB)")
        root.geometry("880x640")
        root.minsize(760, 560)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.notebook = ttk.Notebook(root)
        self.tab_embed = ttk.Frame(self.notebook)
        self.tab_extract = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_embed, text="Embed")
        self.notebook.add(self.tab_extract, text="Extract")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Embed UI
        self._build_embed_tab()
        self._build_extract_tab()

        self.status = tk.StringVar(value="Ready.")
        statusbar = ttk.Label(root, textvariable=self.status, anchor="w")
        statusbar.pack(fill=tk.X, side=tk.BOTTOM)

    # --- Helpers ---
    def warn_jpeg(self, path: str):
        if path.lower().endswith((".jpg", ".jpeg")):
            messagebox.showwarning("JPEG not supported",
                                   "JPEG is lossy and will destroy hidden data. Please use PNG or BMP.")

    def compute_capacity(self, path: str) -> int:
        with Image.open(path) as im:
            im = check_image_mode(im)
            return img_capacity_bytes(im)

    def pretty_size(self, n: int) -> str:
        units = ["B", "KB", "MB", "GB"]
        i = 0
        val = float(n)
        while val >= 1024 and i < len(units) - 1:
            val /= 1024
            i += 1
        return f"{val:.2f} {units[i]}"

    # --- Embed Tab ---
    def _build_embed_tab(self):
        f = self.tab_embed
        padding = {"padx": 10, "pady": 8}

        # Carrier image
        frm_img = ttk.LabelFrame(f, text="Carrier Image (PNG/BMP)")
        frm_img.pack(fill=tk.X, **padding)
        self.embed_img_path = tk.StringVar()
        e_img = ttk.Entry(frm_img, textvariable=self.embed_img_path)
        e_img.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=6)
        ttk.Button(frm_img, text="Browse", command=self.pick_carrier).pack(side=tk.LEFT, padx=6, pady=6)
        if TKDND_AVAILABLE:
            self._enable_dnd(e_img, self.embed_img_path)

        # Payload type
        frm_payload = ttk.LabelFrame(f, text="Payload")
        frm_payload.pack(fill=tk.BOTH, expand=True, **padding)

        self.payload_mode = tk.StringVar(value="text")
        rb1 = ttk.Radiobutton(frm_payload, text="Text", variable=self.payload_mode, value="text", command=self._toggle_payload)
        rb2 = ttk.Radiobutton(frm_payload, text="File", variable=self.payload_mode, value="file", command=self._toggle_payload)
        rb1.grid(row=0, column=0, sticky="w", padx=6, pady=6)
        rb2.grid(row=0, column=1, sticky="w", padx=6, pady=6)

        # Text widget
        self.txt_payload = tk.Text(frm_payload, height=10)
        self.txt_payload.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=6, pady=6)
        frm_payload.rowconfigure(1, weight=1)
        frm_payload.columnconfigure(2, weight=1)

        # File picker
        self.payload_file_path = tk.StringVar()
        self.entry_file = ttk.Entry(frm_payload, textvariable=self.payload_file_path)
        self.btn_browse_file = ttk.Button(frm_payload, text="Choose File", command=self.pick_payload_file)
        if TKDND_AVAILABLE:
            self._enable_dnd(self.entry_file, self.payload_file_path)

        # Encryption
        frm_sec = ttk.Frame(f)
        frm_sec.pack(fill=tk.X, **padding)
        ttk.Label(frm_sec, text="Passphrase (optional for AES-256)").pack(side=tk.LEFT, padx=6)
        self.passphrase = tk.StringVar()
        self.ent_pass = ttk.Entry(frm_sec, textvariable=self.passphrase, show="•")
        self.ent_pass.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Checkbutton(frm_sec, text="Show", command=lambda: self.ent_pass.config(show="" if self.ent_pass.cget("show") else "•")).pack(side=tk.LEFT)

        # Output path
        frm_out = ttk.LabelFrame(f, text="Output (stego image)")
        frm_out.pack(fill=tk.X, **padding)
        self.out_path = tk.StringVar()
        ttk.Entry(frm_out, textvariable=self.out_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=6)
        ttk.Button(frm_out, text="Save As…", command=self.pick_output).pack(side=tk.LEFT, padx=6, pady=6)

        # Actions
        frm_actions = ttk.Frame(f)
        frm_actions.pack(fill=tk.X, **padding)
        self.lbl_capacity = ttk.Label(frm_actions, text="Capacity: — / Needed: —")
        self.lbl_capacity.pack(side=tk.LEFT)
        ttk.Button(frm_actions, text="Check Capacity", command=self.update_capacity).pack(side=tk.RIGHT)
        ttk.Button(frm_actions, text="Embed", command=self.do_embed).pack(side=tk.RIGHT, padx=6)

        self._toggle_payload()  # set initial layout

    def _enable_dnd(self, entry_widget: tk.Widget, stringvar: tk.StringVar):
        root = self.root  # type: ignore
        if not TKDND_AVAILABLE:
            return
        try:
            entry_widget.drop_target_register(DND_FILES)
            def _on_drop(event):
                path = event.data
                if path.startswith("{") and path.endswith("}"):
                    path = path[1:-1]
                stringvar.set(path)
            entry_widget.dnd_bind('<<Drop>>', _on_drop)
        except Exception:
            pass

    def _toggle_payload(self):
        mode = self.payload_mode.get()
        if mode == "text":
            self.txt_payload.grid()
            self.entry_file.grid_forget()
            self.btn_browse_file.grid_forget()
        else:
            self.txt_payload.grid_forget()
            self.entry_file.grid(row=1, column=0, sticky="ew", padx=6, pady=6)
            self.btn_browse_file.grid(row=1, column=1, sticky="w", padx=6, pady=6)

    def pick_carrier(self):
        path = filedialog.askopenfilename(title="Choose carrier image", filetypes=[("Images", "*.png *.bmp *.jpg *.jpeg"), ("All", "*.*")])
        if path:
            self.embed_img_path.set(path)
            self.warn_jpeg(path)

    def pick_payload_file(self):
        path = filedialog.askopenfilename(title="Choose payload file")
        if path:
            self.payload_file_path.set(path)

    def pick_output(self):
        path = filedialog.asksaveasfilename(title="Save stego image as…", defaultextension=".png", filetypes=[("PNG", "*.png"), ("BMP", "*.bmp")])
        if path:
            self.out_path.set(path)

    def update_capacity(self):
        try:
            img = self.embed_img_path.get().strip()
            if not img:
                raise ValueError("Select a carrier image first.")
            cap = self.compute_capacity(img)
            will_encrypt = bool(self.passphrase.get().strip())
            if self.payload_mode.get() == "text":
                data = self.txt_payload.get("1.0", tk.END).encode("utf-8")
                name = ""
            else:
                path = self.payload_file_path.get().strip()
                if not path:
                    raise ValueError("Choose a payload file or switch to Text mode.")
                data = open(path, "rb").read()
                name = os.path.basename(path)
            plan = plan_embedding(img, len(zlib.compress(data, 9)), name, will_encrypt)
            self.lbl_capacity.config(text=f"Capacity: {self.pretty_size(plan.capacity_bytes)} / Needed: {self.pretty_size(plan.needed_bytes)} — {'OK' if plan.fits else 'Too big'}")
        except Exception as e:
            messagebox.showerror("Capacity", str(e))

    def do_embed(self):
        try:
            img = self.embed_img_path.get().strip()
            if not img:
                raise ValueError("Choose a carrier image.")
            self.warn_jpeg(img)
            outp = self.out_path.get().strip()
            if not outp:
                raise ValueError("Choose an output path.")

            if self.payload_mode.get() == "text":
                raw = self.txt_payload.get("1.0", tk.END).encode("utf-8")
                name = ""
            else:
                fpath = self.payload_file_path.get().strip()
                if not fpath:
                    raise ValueError("Choose a payload file.")
                with open(fpath, "rb") as f:
                    raw = f.read()
                name = os.path.basename(fpath)

            passphrase = self.passphrase.get().strip() or None
            embed(img, outp, raw, name, passphrase)
            self.status.set(f"Embedded successfully into {outp}")
            messagebox.showinfo("Done", f"Embedded successfully into:\n{outp}")
        except Exception as e:
            messagebox.showerror("Embed Error", str(e))
            self.status.set(f"Error: {e}")

    # --- Extract Tab ---
    def _build_extract_tab(self):
        f = self.tab_extract
        padding = {"padx": 10, "pady": 8}

        frm_img = ttk.LabelFrame(f, text="Stego Image (PNG/BMP with hidden data)")
        frm_img.pack(fill=tk.X, **padding)
        self.extract_img_path = tk.StringVar()
        e_img = ttk.Entry(frm_img, textvariable=self.extract_img_path)
        e_img.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, pady=6)
        ttk.Button(frm_img, text="Browse", command=self.pick_extract_image).pack(side=tk.LEFT, padx=6, pady=6)
        if TKDND_AVAILABLE:
            self._enable_dnd(e_img, self.extract_img_path)

        frm_pass = ttk.Frame(f)
        frm_pass.pack(fill=tk.X, **padding)
        ttk.Label(frm_pass, text="Passphrase (if encrypted)").pack(side=tk.LEFT, padx=6)
        self.extract_pass = tk.StringVar()
        ent = ttk.Entry(frm_pass, textvariable=self.extract_pass, show="•")
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Checkbutton(frm_pass, text="Show", command=lambda: ent.config(show="" if ent.cget("show") else "•")).pack(side=tk.LEFT)

        frm_actions = ttk.Frame(f)
        frm_actions.pack(fill=tk.X, **padding)
        ttk.Button(frm_actions, text="Extract", command=self.do_extract).pack(side=tk.RIGHT)

        self.extract_info = tk.StringVar(value="—")
        ttk.Label(f, textvariable=self.extract_info, relief=tk.SUNKEN, anchor="w").pack(fill=tk.X, padx=10, pady=6)

    def pick_extract_image(self):
        path = filedialog.askopenfilename(title="Choose stego image", filetypes=[("Images", "*.png *.bmp *.jpg *.jpeg"), ("All", "*.*")])
        if path:
            self.extract_img_path.set(path)

    def do_extract(self):
        try:
            img = self.extract_img_path.get().strip()
            if not img:
                raise ValueError("Choose a stego image.")
            plain, is_file, name = extract(img, self.extract_pass.get().strip() or None)
            if is_file:
                # Ask where to save
                initial = name if name else "recovered.bin"
                outp = filedialog.asksaveasfilename(title="Save recovered file as…", initialfile=initial)
                if outp:
                    with open(outp, "wb") as f:
                        f.write(plain)
                    messagebox.showinfo("Recovered", f"File saved to:\n{outp}")
                    self.extract_info.set(f"Recovered file → {outp}")
            else:
                # Show text in popup
                try:
                    text = plain.decode("utf-8")
                except UnicodeDecodeError:
                    text = plain.decode("utf-8", errors="replace")
                win = tk.Toplevel(self.root)
                win.title("Recovered Text")
                txt = tk.Text(win, wrap=tk.WORD)
                txt.pack(fill=tk.BOTH, expand=True)
                txt.insert("1.0", text)
                self.extract_info.set("Recovered text shown in a new window.")
        except Exception as e:
            messagebox.showerror("Extract Error", str(e))
            self.extract_info.set(f"Error: {e}")


def main():
    Root = TkinterDnD.Tk if TKDND_AVAILABLE else tk.Tk
    root = Root()
    app = StegoBoxApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
# --- End of StegoBox ---