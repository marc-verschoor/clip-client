import sys
import io
import logging

try:
    from PIL import ImageGrab, Image
except ImportError:
    ImageGrab = None
    Image = None

import pyperclip

# Try to import GTK for Linux clipboard image support
GTK_AVAILABLE = False
try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk, GLib
    GTK_AVAILABLE = True
except Exception as e:
    GTK_AVAILABLE = False
    logging.debug(f"GTK not available: {e}")

def get_clipboard_content():
    """
    Returns a tuple (type, data):
    - type: 'text', 'image', or 'none'
    - data: str for text, bytes for image, None for none
    """
    # Try image first (if supported)
    if sys.platform in ("win32", "darwin") and ImageGrab is not None:
        try:
            img = ImageGrab.grabclipboard()
            if isinstance(img, Image.Image):
                with io.BytesIO() as output:
                    img.save(output, format="PNG")
                    logging.debug("Clipboard image detected (PNG)")
                    return ("image", output.getvalue())
            elif img is not None:
                logging.debug(f"Clipboard contains non-image data: {type(img)}")
            else:
                logging.debug("Clipboard does not contain an image (ImageGrab.grabclipboard() returned None)")
        except Exception as e:
            logging.debug(f"Exception in ImageGrab.grabclipboard(): {e}")
    elif sys.platform.startswith("linux") and GTK_AVAILABLE:
        try:
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            # Try to get image (pixbuf) from clipboard
            pixbuf = clipboard.wait_for_image()
            if pixbuf:
                # Convert GdkPixbuf to PNG bytes
                buf = io.BytesIO()
                pixbuf.save_to_callback(lambda b, d: buf.write(d), "png", user_data=None)
                data = buf.getvalue()
                logging.debug("Clipboard image detected (GTK, PNG)")
                return ("image", data)
            else:
                logging.debug("Clipboard does not contain an image (GTK wait_for_image returned None)")
        except Exception as e:
            logging.debug(f"Exception in GTK clipboard image access: {e}")
    else:
        if sys.platform.startswith("linux") and not GTK_AVAILABLE:
            logging.debug("GTK not available: install PyGObject for image clipboard support on Linux.")
        else:
            logging.debug("Image clipboard not supported on this platform or Pillow not installed.")
    # Fallback to text
    try:
        text = pyperclip.paste()
        if text:
            logging.debug("Clipboard text detected.")
            return ("text", text)
        else:
            logging.debug("Clipboard text is empty.")
    except UnicodeDecodeError as ude:
        logging.debug(f"Clipboard contains non-text (binary) data, cannot decode as UTF-8: {ude}")
    except Exception as e:
        logging.debug(f"Exception in pyperclip.paste(): {e}")
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
        if sys.platform in ("win32", "darwin"):
            logging.debug("Setting image clipboard is not implemented for Windows/macOS in this example.")
        elif sys.platform.startswith("linux") and GTK_AVAILABLE:
            try:
                clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
                # Load PNG bytes into GdkPixbuf
                loader = Gdk.PixbufLoader.new_with_type("png")
                loader.write(data)
                loader.close()
                pixbuf = loader.get_pixbuf()
                clipboard.set_image(pixbuf)
                clipboard.store()
                logging.debug("Image set to clipboard (GTK)")
            except Exception as e:
                logging.debug(f"Exception setting image clipboard (GTK): {e}")
        else:
            logging.debug("Image clipboard set not supported on this platform.")
    else:
        pass
