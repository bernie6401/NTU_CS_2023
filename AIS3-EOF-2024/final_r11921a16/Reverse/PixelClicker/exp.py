from PIL import Image
data = open('./MEM_000002843342A076_0015F900_flag.mem', 'rb').read()

img = Image.frombytes("RGBA", (600, 600), data)
img = img.transpose(Image.FLIP_TOP_BOTTOM)
img.save('flag.png', 'png')