import PIL
from PIL import ImageFont
from PIL import Image
from PIL import ImageDraw

def text2png(text, fullpath, color = "#000", bgcolor = "#FFF", fontsize = 30, padding = 10):
	font = ImageFont.truetype("arial.ttf", fontsize)

	width = font.getsize(max(text.split('\n'), key = len))[0] + (padding * 2)
	line_height = font.getsize(text)[1]
	img_height = line_height * (len(text.split('\n')) + 1) + padding
	img = Image.new("RGBA", (width, img_height), bgcolor)
	draw = ImageDraw.Draw(img)

	y = padding
	for line in text.split('\n'):
		draw.text((padding, y), line, color, font=font)
		y += line_height

	img.save(fullpath)

data = '''Accepted cipher suites for TLS 1.1 (deprecated):
* TLS_RSA_WITH_AES_256_CBC_SHA
* TLS_RSA_WITH_AES_128_CBC_SHA
* TLS_RSA_WITH_3DES_EDE_CBC_SHA
* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHAasdafasdasdafsfasdwqqf
* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'''

text2png(data, 'test.png')