import sys
import string
import re
from elftools.elf.elffile import ELFFile
import struct
from collections import Counter

def getELFHeader(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
    return elffile.header

def readfile(filename):
    with open(filename, "rb") as f:
        content = f.read()
    return content

def slidewindow(iterable, size=1):
    i = iter(iterable)
    win = []
    for e in range(0, size):
        win.append(next(i))
    yield win
    for e in i:
        win = win[1:] + [e]
        yield win

def strings(filename):
    min = 3
    with open(filename, errors="ignore") as f:
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:
            yield result

def filterstrings(strings):
    relevantstrings = re.findall("[a-zA-Z]{3,}$", strings)

#^((?!PART).)*$
#[a-zA-Z0-9]{3,}$

#------------MAIN FUNCTION:------------

#Read a file:
samplebinary = readfile("sample_exe64.elf")
#print(samplebinary)
#print(type(samplebinary))

#Possible values of a byte:
bytepossiblevalues = []
for i in range(0x00, 0xff):
    bytepossiblevalues.append(i)

#Split into 1 byte sections:
ngramslist = []
for value in slidewindow(samplebinary,1):
    ngramslist.append(value)
ngrams = [y for x in ngramslist for y in x]

#Get occurences of possible bytes:
byte_occurence = []
for i in range(0,255):
    byte_occurence.append(0)

#Count each member occurence in the 1 byte sections: (misses if a byte occurs 0 times)
#print(Counter(ngrams))

#Check the 1 byte sections, count the occurence bytes
for bytevalue in ngrams:
    for i in range (0,255):
        if (bytevalue == i):
            byte_occurence[i] += 1
print("Occurences of bytes 0-255: ")
print(byte_occurence)

#Read the header in a file:
print("\nPrint the header:")
print(getELFHeader("sample_exe64.elf"))

#Read strings in a file:
print("\nPrint the strings:")

for s in strings("sample_exe64.elf"):
    print(s)
    print(re.findall("[0-9a-zA-Z:\.@-_\/]{3,}", s))
