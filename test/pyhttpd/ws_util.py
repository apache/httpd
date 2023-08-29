import logging
import struct


log = logging.getLogger(__name__)


class WsFrame:

    CONT = 0
    TEXT = 1
    BINARY = 2
    RSVD3 = 3
    RSVD4 = 4
    RSVD5 = 5
    RSVD6 = 6
    RSVD7 = 7
    CLOSE = 8
    PING = 9
    PONG = 10
    RSVD11 = 11
    RSVD12 = 12
    RSVD13 = 13
    RSVD14 = 14
    RSVD15 = 15

    OP_NAMES = [
        "CONT",
        "TEXT",
        "BINARY",
        "RSVD3",
        "RSVD4",
        "RSVD5",
        "RSVD6",
        "RSVD7",
        "CLOSE",
        "PING",
        "PONG",
        "RSVD11",
        "RSVD12",
        "RSVD13",
        "RSVD14",
        "RSVD15",
    ]

    def __init__(self, opcode: int, fin: bool, mask: bytes, data: bytes):
        self.opcode = opcode
        self.fin = fin
        self.mask = mask
        self.data = data
        self.length = len(data)

    def __repr__(self):
        return f'WsFrame[{self.OP_NAMES[self.opcode]} fin={self.fin}, mask={self.mask}, len={len(self.data)}]'

    @property
    def data_len(self) -> int:
        return len(self.data) if self.data else 0

    def to_network(self) -> bytes:
        nd = bytearray()
        h1 = self.opcode
        if self.fin:
            h1 |= 0x80
        nd.extend(struct.pack("!B", h1))
        mask_bit = 0x80 if self.mask is not None else 0x0
        h2 = self.data_len
        if h2 > 65535:
            nd.extend(struct.pack("!BQ", 127|mask_bit, h2))
        elif h2 > 126:
            nd.extend(struct.pack("!BH", 126|mask_bit, h2))
        else:
            nd.extend(struct.pack("!B", h2|mask_bit))
        if self.mask is not None:
            nd.extend(self.mask)
        if self.data is not None:
            nd.extend(self.data)
        return nd

    @classmethod
    def client_ping(cls, data: bytes, mask: bytes = None) -> 'WsFrame':
        if mask is None:
            mask = bytes.fromhex('00 00 00 00')
        return WsFrame(opcode=WsFrame.PING, fin=True, mask=mask, data=data)

    @classmethod
    def client_close(cls, code: int, reason: str = None,
                     mask: bytes = None) -> 'WsFrame':
        data = bytearray(struct.pack("!H", code))
        if reason is not None:
            data.extend(reason.encode())
        if mask is None:
            mask = bytes.fromhex('00 00 00 00')
        return WsFrame(opcode=WsFrame.CLOSE, fin=True, mask=mask, data=data)


class WsFrameReader:

    def __init__(self, data: bytes):
        self.data = data

    def _read(self, n: int):
        if len(self.data) < n:
            raise EOFError(f'have {len(self.data)} bytes left, but {n} requested')
        elif n == 0:
            return b''
        chunk = self.data[:n]
        del self.data[:n]
        return chunk

    def next_frame(self):
        data = self._read(2)
        h1, h2 = struct.unpack("!BB", data)
        log.debug(f'parsed h1={h1} h2={h2} from {data}')
        fin = True if h1 & 0x80 else False
        opcode = h1 & 0xf
        has_mask = True if h2 & 0x80 else False
        mask = None
        dlen = h2 & 0x7f
        if dlen == 126:
            (dlen,) = struct.unpack("!H", self._read(2))
        elif dlen == 127:
            (dlen,) = struct.unpack("!Q", self._read(8))
        if has_mask:
            mask = self._read(4)
        return WsFrame(opcode=opcode, fin=fin, mask=mask, data=self._read(dlen))

    def eof(self):
        return len(self.data) == 0

    @classmethod
    def parse(cls, data: bytes):
        frames = []
        reader = WsFrameReader(data=data)
        while not reader.eof():
            frames.append(reader.next_frame())
        return frames
