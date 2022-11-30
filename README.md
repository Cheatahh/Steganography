## STEG Steganography Tool

This is a simple steganography tool that can be used to hide content in images. 

It uses the least significant bits of each pixel to store binary encoded values, resulting in a slight change of color. While encoded data isn´t really hidden, it is very hard to spot with the naked eye. 

### To know

When applying this technique to images, it is important to keep in mind that the image should be large enough to hold the data. The more data you want to hide, the larger the image should be. The rough available space (minus some internal encoding) can be queried with `steg.py size IMAGE`.

Additionally, make sure, the output image is encoded in a _lossless_ format. Lossy compression, such as JPEG, specializes on discarding any data, the human eye can´t really grasp anyway (what we are trying to exploit). As STEG uses `imageio` to read and write images, there are plenty of lossless image formats available. PNG is always a good choice.

### Usage

As of version 0.1, STEG supports the following content / payload types:

* Text with `-t TEXT`
* Files with `-f FILENAME`

These arguments can repeat multiple times to encode multiple files or text snippets.
Use the `pack` and `unpack` actions to move data respectively.

Image channel usage and order, as well as the number of bits used to encode data can be configured. See `steg.py -h` for details.

**Encoding / Packing Example**

`steg.py pack example/original.png -o encoded.png -f example/supersecret.txt`

**Decoding / Unpacking Example**

`steg.py unpack encoded.png -o out_folder`
