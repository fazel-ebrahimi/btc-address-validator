# Bitcoin Address Validator (No External Libraries)

A simple and lightweight Python script to validate Bitcoin addresses without any external dependencies.  
Supports Legacy (P2PKH), P2SH, and Bech32 (SegWit) address formats by checking their structure and checksum manually.

---

## Features

- Validate Legacy (starting with '1'), P2SH (starting with '3'), and Bech32 (starting with 'bc1' or 'tb1') addresses  
- No external libraries required — pure Python implementation  
- Command-line interactive input for easy use  
- Comprehensive checksum verification for Base58Check and Bech32 formats  

---

## Usage

1. Clone or download the repository.  
2. Run the script:

```bash
python btc_address_validator.py
