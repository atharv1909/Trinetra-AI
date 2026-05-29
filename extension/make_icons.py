from PIL import Image, ImageDraw
import os

os.makedirs('icons', exist_ok=True)
for size in [16, 48, 128]:
    img = Image.new('RGBA', (size, size), (15, 15, 15, 255))
    draw = ImageDraw.Draw(img)
    draw.ellipse([size//8, size//8, size-size//8, size-size//8], outline=(99, 102, 241, 255), width=max(1, size//16))
    img.save(f'icons/icon{size}.png')
    print(f'Created icon{size}.png')