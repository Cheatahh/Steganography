#! python3

"""

    STEG Steganography Tool
    Author: Cheatahh (https://github.com/Cheatahh)
    License: GNU General Public License v3.0, https://www.gnu.org/licenses/gpl-3.0.html

"""

import argparse
import os
import sys

import imageio as iio
import imageio.v2 as imageio

import numpy


steg_version = 0.1

__ansi_red = '\033[31m'
__ansi_white = '\033[97m'
__ansi_blue = '\033[94m'
__ansi_green = '\033[92m'
__ansi_reset = '\033[0m'


# Section IO
def __read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()


def __write_file(filename, content):
    directory = os.path.dirname(filename)
    if directory != '':
        os.makedirs(directory, exist_ok=True)
    with open(filename, 'wb') as file:
        file.write(content)


def __read_image(image, use_channels, bits_per_channel):
    if type(image) == str:
        image = imageio.imread(image)
    if type(image) != iio.core.util.Array:
        raise TypeError('Image must be a numpy.ndarray or a string')
    if use_channels is not None:
        for channel in use_channels:
            assert channel >= 0, \
                f'Value *use_channels must be >= 0'
    else:
        use_channels = range(image.shape[2])
    assert bits_per_channel >= 0, \
        'Value bits_per_channel must be >= 0'
    assert len(image.shape) == 3, 'File has to contain a single image'
    assert issubclass(type(image[0, 0, 0]), numpy.integer), 'Floating point images are not supported'
    assert image.shape[2] > max(use_channels), \
        f'Image has not enough channels (required >= {max(use_channels) + 1}, contains {image.shape[2]})'
    assert numpy.iinfo(image.dtype).bits >= bits_per_channel, \
        f'Image has not enough bits per channel (required >= {bits_per_channel}, contains {numpy.iinfo(image.dtype).bits})'
    return image, use_channels


def __write_image(filename, image):
    directory = os.path.dirname(filename)
    if directory != '':
        os.makedirs(directory, exist_ok=True)
    imageio.imwrite(filename, image)


# Section Util
def __image_size(image, use_channels, bits_per_channel):
    return (image.shape[0] * image.shape[1] * len(use_channels) * bits_per_channel) // 8


def __pack(data, int_size=4):
    size = len(data).to_bytes(int_size, 'big')
    return size + data


def __unpack(data, int_size=4, offset=0):
    size = int.from_bytes(data[offset:offset + int_size], 'big')
    return size, data[offset + int_size:offset + int_size + size]


def __pack_payload_text(entry, **kwargs):
    text = entry['text']
    payload = __pack(text.encode('utf-8'))
    if kwargs.get('cli_mode', False):
        print(f"{__ansi_green}+{__ansi_reset} text '{text}' (packed {len(payload) + 1} bytes)")
    return payload


def __unpack_payload_text(payload, **kwargs):
    size, payload = __unpack(payload)
    text = payload.decode('utf-8')
    if kwargs.get('cli_mode', False):
        print(f"{__ansi_blue}>{__ansi_reset} text '{text}' (unpacked {size + 5} bytes)")
    return size + 4, {'type': 'text', 'text': text}


def __pack_payload_file(entry, **kwargs):
    filename = entry['filename']
    filename_payload = __pack(filename.encode('utf-8'), 2)
    assert len(filename_payload) < 2 << 8, 'Filename is too long'
    payload = filename_payload + __pack(__read_file(filename))
    if kwargs.get('cli_mode', False):
        print(f"{__ansi_green}+{__ansi_reset} file '{filename}' (packed {len(payload) + 1} bytes)")
    return payload


def __unpack_payload_file(payload, **kwargs):
    size, filename = __unpack(payload, 2)
    filename = filename.decode('utf-8')
    payload_size, payload = __unpack(payload, offset=size + 2)
    if kwargs.get('cli_mode', False):
        print(f"{__ansi_blue}>{__ansi_reset} file '{filename}' (unpacked {size + 2 + payload_size + 4 + 1} bytes)")
        directory = kwargs.get('output', "./")
        __write_file(os.path.join(directory, filename), payload)
    return size + 2 + payload_size + 4, {'type': 'file', 'filename': filename, 'data': payload}


__payload_types = {
    'text': (b'\x00', __pack_payload_text, __unpack_payload_text),
    'file': (b'\x01', __pack_payload_file, __unpack_payload_file)
}
__payload_types_unpack = {opcode[0]: unpack for opcode, _, unpack in __payload_types.values()}


def __pack_payloads(payloads, **kwargs):
    payload = b''
    for entry in payloads:
        payload_type = entry['type']
        if payload_type not in __payload_types:
            raise ValueError(f'Unknown payload type {payload_type}')
        opcode, pack, _ = __payload_types[payload_type]
        payload = payload + opcode + pack(entry, **kwargs)
    return payload


def __unpack_payloads(payload_data, **kwargs):
    offset = 0
    result = []
    while offset < len(payload_data):
        opcode = payload_data[offset]
        if opcode not in __payload_types_unpack:
            raise ValueError(f'Unknown payload opcode {opcode}')
        unpack = __payload_types_unpack[opcode]
        consumed, payload = unpack(payload_data[offset + 1:], **kwargs)
        result.append(payload)
        offset += consumed + 1
    return result


# Section Coding
def __write_payload(image, use_channels, bits_per_channel, payload):
    payload = len(payload).to_bytes(4, 'big') + payload
    size = len(payload)
    assert size <= __image_size(image, use_channels, bits_per_channel), f'Payload too large (required {len(payload)} bytes, max {size} bytes)'
    size *= 8
    index = 0
    for x in range(image.shape[0]):
        for y in range(image.shape[1]):
            for c in use_channels:
                value = image[x, y, c]
                value &= ~((1 << bits_per_channel) - 1)
                for i in range(bits_per_channel):
                    if index == size:
                        return
                    value |= ((payload[index // 8] >> (7 - index % 8)) & 1) << i
                    index += 1
                image[x, y, c] = value
    assert index == index, 'Internal Error'


def __read_payload(image, use_channels, bits_per_channel):
    def read_bytes(size):
        assert size <= __image_size(image, use_channels, bits_per_channel), 'Requested payload too large'
        payload = bytearray(size)
        size *= 8
        index = 0
        for x in range(image.shape[0]):
            for y in range(image.shape[1]):
                for c in use_channels:
                    value = image[x, y, c]
                    for i in range(bits_per_channel):
                        if index == size:
                            return payload
                        payload[index // 8] |= ((value >> i) & 1) << (7 - index % 8)
                        index += 1
        assert size == index, 'Internal Error'
    payload_size = int.from_bytes(read_bytes(4), 'big')
    return read_bytes(payload_size + 4)[4:]


# Section Steg
def steg_size(image, use_channels, bits_per_channel, **kwargs):
    result, used_channels = __read_image(image, use_channels, bits_per_channel)
    size = __image_size(result, used_channels, bits_per_channel)
    cli_mode = kwargs.get('cli_mode', False)
    if cli_mode:
        print(f"""{__ansi_blue}~{__ansi_reset} image '{image}' ({result.shape[0]}x{result.shape[1]} pixels, {
        result.shape[2]} channels)\n  available: {__ansi_green}{size}{__ansi_reset} bytes""")
    return result, size, used_channels


def steg_pack(image, use_channels, bits_per_channel, payloads, **kwargs):
    result, _, used_channels = steg_size(image, use_channels, bits_per_channel, **kwargs)
    payload = __pack_payloads(payloads, **kwargs)
    __write_payload(result, used_channels, bits_per_channel, payload)
    output_image = kwargs.get('output', None)
    if output_image is not None:
        __write_image(output_image, result)
    return result


def steg_unpack(image, use_channels, bits_per_channel, **kwargs):
    result, _, used_channels = steg_size(image, use_channels, bits_per_channel, **kwargs)
    payload = __read_payload(result, used_channels, bits_per_channel)
    payloads = __unpack_payloads(payload, **kwargs)
    return payloads


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=f"""{__ansi_white}STEG Steganography Tool {
    __ansi_blue}v{steg_version}{__ansi_reset}\nAuthor: Cheatahh (https://github.com/Cheatahh)\nLicense: GNU General Public License v3.0, https://www.gnu.org/licenses/gpl-3.0.html""")

    parser.add_argument(dest="action", action="store", choices=['size', 'pack', 'unpack'], type=str, help='action to perform')
    parser.add_argument(dest="image", action="store", type=str, help='input image to use')
    parser.add_argument("-o", dest="output", action="store", type=str, help='output depending on action (directory for unpack, output image for pack)')
    parser.add_argument("-c", dest="channels", action="store", type=str, help='channels to use (default: all)', default='all')
    parser.add_argument("-b", dest="bits", action="store", type=int, help='bits per channel to use (default: 1)', default=1)
    parser.add_argument("-t", dest="text_payload", action="append", type=str, help='text payload to pack', default=[])
    parser.add_argument("-f", dest="file_payload", action="append", type=str, help='file payload to pack', default=[])

    namespace = parser.parse_args(sys.argv[1:])

    try:
        channels = None if namespace.channels == 'all' else [ord(char) - ord('0') for char in namespace.channels]
        if channels is not None:
            for idx, _channel in enumerate(channels):
                assert 0 <= _channel <= 9, f"Invalid channel '{namespace.channels[idx]}'"

        # noinspection PyTypeChecker
        config = {
            'image': namespace.image,
            'output': namespace.output,
            'use_channels': channels,
            'bits_per_channel': namespace.bits,
            'payloads': [{'type': 'text', 'text': text} for text in namespace.text_payload] +
                        [{'type': 'file', 'filename': file} for file in namespace.file_payload],
            'cli_mode': True
        }

        actions = {
            'size': steg_size,
            'pack': steg_pack,
            'unpack': steg_unpack
        }

        actions[namespace.action](**config)

    except AssertionError as err:
        print(f'{__ansi_red}{err}{__ansi_reset}')
        exit(1)
