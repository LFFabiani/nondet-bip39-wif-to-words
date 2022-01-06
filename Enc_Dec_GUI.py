#importing mmodules
import base58
import binascii
from tkinter import *
from bitstring import BitArray
from mnemonic import Mnemonic
import hashlib
import pyperclip as pc

# initialize window
root = Tk()
root.geometry('900x300')
root.resizable(0, 0)

# title of the window
root.title("Bitcoin - BIP39 Non Deterministic WIF Encode Decode")

# label
Label(root, text='Private Key x 24 words', font='arial 12 bold').pack()
Label(root, text='( 256 bits + 8 checksum bits ) = ( 11 bit x 24 BIP39 words )', font='arial 12').pack()
Label(root, text='Input WIF to get Words (mode e)', font='arial 12').pack()
Label(root, text='Input 24 space separated words to get WIF (mode d)', font='arial 12').pack()

# define variables
Input = StringVar()
mode = StringVar()
Result = StringVar()


# base58 alphabet
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
mnemo = Mnemonic("english")

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def getWif(privkey):
    wif = b"\x80" + privkey
    wif = b58(wif + sha256h(sha256h(wif))[:4])
    return wif

def b58(data):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    if data[0] == 0:
        return "1" + b58(data[1:])

    x = sum([v * (256 ** i) for i, v in enumerate(data[::-1])])
    ret = ""
    while x > 0:
        ret = B58[x % 58] + ret
        x = x // 58

    return ret

def sha256(arg) :
	''' Return a sha256 hash of a hex string '''
	byte_array = bytearray.fromhex(arg)
	m = hashlib.sha256()
	m.update(byte_array)
	return m.hexdigest()


def sha256h(data):
    digest = hashlib.new("sha256")
    digest.update(data)
    return digest.digest()

def b58encode(hex_string) :
	''' Return a base58 encoded string from hex string '''
	num = int(hex_string, 16)
	encode = ""
	base_count = len(alphabet)
	while (num > 0) :
		num, res = divmod(num,base_count)
		encode = alphabet[res] + encode
	return encode

def b58decode(v):
	''' Decode a Base58 encoded string as an integer and return a hex string '''
	if not isinstance(v, str):
		v = v.decode('ascii')
	decimal = 0
	for char in v:
		decimal = decimal * 58 + alphabet.index(char)
	return hex(decimal)[2:] # (remove "0x" prefix)

def wifChecksum(wif, verbose=False) :
	''' Returns True if the WIF is positive to the checksum, False otherwise '''
	# 1 - Take the Wallet Import Format string
	if verbose : print("WIF: " + wif)
	# 2 - Convert it to a byte string using Base58Check encoding
	byte_str = b58decode(wif)
	if verbose : print("WIF base58 decoded: " + byte_str)
	# 3 - Drop the last 4 checksum bytes from the byte string
	byte_str_drop_last_4bytes = byte_str[0:-8]
	if verbose : print("Decoded WIF drop last 4 bytes: " + byte_str_drop_last_4bytes)
	# 3 - Perform SHA-256 hash on the shortened string 
	sha_256_1 = sha256(byte_str_drop_last_4bytes)
	if verbose : print("SHA256 1: " + sha_256_1)
	# 4 - Perform SHA-256 hash on result of SHA-256 hash 
	sha_256_2 = sha256(sha_256_1)
	if verbose : print("SHA256 2: " + sha_256_2)
	# 5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum 
	first_4_bytes = sha_256_2[0:8]
	if verbose : print("First 4 bytes: " + first_4_bytes)
	# 6 - Make sure it is the same, as the last 4 bytes from point 2 
	last_4_bytes_WIF = byte_str[-8:]
	if verbose : print("Last 4 bytes of WIF: " + last_4_bytes_WIF)
	bytes_check = False
	if first_4_bytes == last_4_bytes_WIF : bytes_check = True
	if verbose : print("4 bytes check: " + str(bytes_check))
	# 7 - If they are, and the byte string from point 2 starts with 0x80 (0xef for testnet addresses), then there is no error.
	check_sum = False
	if bytes_check and byte_str[0:2] == "80" : check_sum = True
	if verbose : print("Checksum: " + str(check_sum))
	return check_sum


# function to encode
def Encode(Input):
	try:
		if  wifChecksum(Input) != True:
			return "Invalid Wif"
		else:
			first_encode = base58.b58decode(Input)
			private_key_full = binascii.hexlify(first_encode)
			private_key = private_key_full[2:-8]
			entropy = bin(int(private_key, 16))[2:]
			entropy = entropy.zfill(256)
			randomBytes = bitstring_to_bytes(entropy)
			words = mnemo.to_mnemonic(randomBytes)
			return words
	except ValueError:
		return "Invalid Wif"

# function to decode
def Decode(Input):
	if mnemo.check(Input) != True:
		return "Invalid Words"
	else:
		randomBytes = mnemo.to_entropy(Input)
		return getWif(randomBytes)

# function to set mode
def Mode():
    if (mode.get() == 'e'):
        Result.set(Encode(Input.get()))
    elif (mode.get() == 'd'):
        Result.set(Decode(Input.get()))
    else:
        Result.set('Invalid Mode')

# Function to exit window
def Exit():
    root.destroy()

# Function to reset
def Reset():
    Input.set("")
    mode.set("")
    Result.set("")

# Function to copy to clipboard	
def Copy():
	pc.copy(Result.get())

# Label and Button

# Input
Label(root, font='arial 10 bold', text='Input').place(x=60, y=100)
Entry(root, font='arial 10', textvariable=Input, bg='ghost white').place(x=310, y=100, width=500)

# mode
Label(root, font='arial 10 bold', text='Mode (e)ncode / (d)ecode to/from Words').place(x=60, y=130)
Entry(root, font='arial 10', textvariable=mode, bg='ghost white').place(x=410, y=130)

# result
Entry(root, font='arial 10 bold', textvariable=Result, bg='ghost white').place(x=310, y=160, width=500)

# result button
Button(root, font='arial 10 bold', text='RESULT', padx=2, bg='LightGray', command=Mode).place(x=210, y=160)

# reset button
Button(root, font='arial 10 bold', text='RESET', width=6, command=Reset, bg='LimeGreen', padx=2).place(x=80, y=240)

# exit button
Button(root, font='arial 10 bold', text='EXIT', width=6, command=Exit, bg='OrangeRed', padx=2, pady=2).place(x=180, y=240)

# copy button
Label(root, font='arial 10 bold', text='Copy Result to Clipboard').place(x=340, y=240)
Button(root, font='arial 10 bold', text='COPY', width=6, command=Copy, bg='Yellow', padx=2, pady=2).place(x=280, y=240)

root.mainloop()