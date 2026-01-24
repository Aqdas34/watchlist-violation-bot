from PIL import Image

def create_ico(input_image_path, output_ico_path):
    img = Image.open(input_image_path)
    # Common ICO sizes
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(output_ico_path, format='ICO', sizes=sizes)
    print(f"Icon saved to {output_ico_path}")

create_ico("resources/logo.png", "icon.ico")