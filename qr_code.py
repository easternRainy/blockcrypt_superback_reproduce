import segno
import base64
from pyzbar.pyzbar import decode
from PIL import Image

def generate_qr_code(data, save_path):
    # data is bytes
    base64_encoded_data = base64.b64encode(data)
    qrcode = segno.make(base64_encoded_data)
    qrcode.save(save_path, scale=5)


def read_qr_code(qr_path):
    # try:

    decoded_data_list = decode(Image.open(qr_path))
    data = base64.b64decode(decoded_data_list[0].data)
    return data
    # except:
    #     return None



if __name__ == "__main__":
    # generate_qr_code(b"abcdef", save_path="assets/test_qr.png")
    decoded_data = read_qr_code("assets/qr_code_0.png")
    # print(decoded_data)