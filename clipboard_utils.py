import sys
import io

try:
    from PIL import ImageGrab, Image
except ImportError:
    ImageGrab = None
    Image = None

import pyperclip


def get_clipboard_content():
    """
    Returns a tuple (type, data):
    - type: 'text', 'image', or 'none'
    - data: str for text, bytes for image, None for none
    """
    # Try image first (if supported)
    if ImageGrab is not None and sys.platform in ("win32", "darwin"):
        try:
            img = ImageGrab.grabclipboard()
            if isinstance(img, Image.Image):
                # Convert to PNG bytes
                with io.BytesIO() as output:
                    img.save(output, format="PNG")
                    return ("image", output.getvalue())
        except Exception:
            pass
    # Fallback to text
    try:
        text = pyperclip.paste()
        if text:
            return ("text", text)
    except Exception:
        pass
    return ("none", None)


def set_clipboard_content(content_type, data):
    """
    Sets clipboard content based on type.
    - content_type: 'text' or 'image'
    - data: str for text, bytes for image
    """
    if content_type == "text":
        pyperclip.copy(data)
    elif content_type == "image":
        if ImageGrab is not None and Image is not None and sys.platform in ("win32", "darwin"):
            try:
                img = Image.open(io.BytesIO(data))
                output = io.BytesIO()
                img.save(output, format="BMP")
                bmp_data = output.getvalue()
                # On Windows, set clipboard using win32clipboard (optional, not implemented here)
                # On macOS, not trivial; would need pbcopy or similar
                # For now, not implemented
                pass
            except Exception:
                pass
        # Not implemented for Linux or if PIL not available
        pass
    else:
        pass
