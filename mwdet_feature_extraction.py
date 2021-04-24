import sys
import os
import string
import struct
from elftools.elf.elffile import ELFFile
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn import datasets

def getELFHeader(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
    return elffile.header

def readfile(fname):
    with open(fname, "rb") as file:
        content = file.read()
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
samplebinary = readfile("test_malware/malware (18)")

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

#Check the 1 byte sections, count the occurence bytes
for bytevalue in ngrams:
    for i in range (0,255):
        if (bytevalue == i):
            byte_occurence[i] += 1

#Print Ngram:
print("Occurences of bytes 0-255: ")
print(byte_occurence)
print(len(byte_occurence))




"""
#Read the header in a file:
print("\nPrint the header:")
print(getELFHeader("sample_exe64.elf"))
print(getELFHeader("samplebinary"))
"""


#-------------ML PART----------------


"""
X, y = datasets.load_iris(return_X_y=True)
print(type(X))
print(type(y))
print(X.shape)
print(y.shape)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=0)

clf = RandomForestClassifier()
clf.fit(X_train, y_train)
print(clf.predict([[0, 0, 0, 0]]))
print(clf.score(X_train, y_train))
print(clf.score(X_test, y_test))
"""