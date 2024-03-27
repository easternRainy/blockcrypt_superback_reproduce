import segno
import base64
from pyzbar.pyzbar import decode
from PIL import Image

def generate_qr_code(data, save_path):
    # data is bytes
    base64_encoded_data = base64.b64encode(data)
    try:
        qrcode = segno.make(base64_encoded_data)
        qrcode.save(save_path, scale=5)
    except:
        raise Exception(f"Generate QR Code for {save_path} failed.")


def read_qr_code(qr_path):
    decoded_data_list = decode(Image.open(qr_path))
    assert decoded_data_list
    data = base64.b64decode(decoded_data_list[0].data)
    return data

if __name__ == "__main__":
    decoded_data = read_qr_code("assets/qr_code_0.png")
