import sys

# -------------------- Base58 --------------------
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_decode(s):
    num = 0
    for char in s:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)
    combined = num.to_bytes(25, byteorder='big')
    return combined

def checksum_is_valid(decoded):
    # checksum = last 4 bytes
    checksum = decoded[-4:]
    # data = everything except checksum
    data = decoded[:-4]
    import hashlib
    hash1 = hashlib.sha256(data).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return checksum == hash2[:4]

def is_valid_base58_address(addr):
    try:
        decoded = base58_decode(addr)
        return checksum_is_valid(decoded)
    except Exception as e:
        return False

# -------------------- Bech32 --------------------
# Reference implementation based on BIP-0173
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(addr):
    if (any(ord(x) < 33 or ord(x) > 126 for x in addr)):
        return (None, None)
    addr = addr.lower()
    pos = addr.rfind('1')
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return (None, None)
    hrp = addr[:pos]
    data = addr[pos+1:]
    decoded = []
    for c in data:
        if c not in CHARSET:
            return (None, None)
        decoded.append(CHARSET.find(c))
    if not bech32_verify_checksum(hrp, decoded):
        return (None, None)
    return (hrp, decoded[:-6])

def is_valid_bech32_address(addr):
    hrp, data = bech32_decode(addr)
    if hrp is None:
        return False
    if hrp not in ['bc', 'tb']:  # mainnet or testnet
        return False
    return True

# -------------------- Main Validator --------------------

def detect_address_type(addr):
    if addr.startswith('1'):
        return 'Legacy (P2PKH)'
    elif addr.startswith('3'):
        return 'P2SH'
    elif addr.lower().startswith('bc1') or addr.lower().startswith('tb1'):
        return 'Bech32 (SegWit)'
    else:
        return 'Unknown'

def validate_btc_address(addr):
    addr_type = detect_address_type(addr)
    if addr_type == 'Legacy (P2PKH)' or addr_type == 'P2SH':
        valid = is_valid_base58_address(addr)
    elif addr_type == 'Bech32 (SegWit)':
        valid = is_valid_bech32_address(addr)
    else:
        valid = False
    return addr_type, valid

def main():
    address = input("Enter Bitcoin address to validate: ").strip()
    addr_type, valid = validate_btc_address(address)
    print(f"Address: {address}")
    print(f"Type: {addr_type}")
    print(f"Valid: {valid}")


if __name__ == "__main__":
    main()
