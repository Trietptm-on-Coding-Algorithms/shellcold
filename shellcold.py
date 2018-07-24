#!/usr/bin/python

from pwn import *
from struct import pack
from sys import stderr
from os import popen
import argparse
import time

def sigint_handler(signum, frame):
    exit()

signal.signal(signal.SIGINT, sigint_handler)
p = argparse.ArgumentParser()
p.add_argument("-c","--arch",dest="arch",default="i386",help="aarch64, alpha, amd64, arm, avr, cris, i386, ia64, m68k, mips, mips64, msp430, powerpc, powerpc64, s390, sparc, sparc64, thumb, vax [default: i386]")
p.add_argument("-a","--asm",action='store_true',help="assemble a readable assembly into bytestring")
p.add_argument("-d","--disasm",action='store_true',help="disassemble a bytestring into human readable assembley")
p.add_argument("-m","--hexdump",action='store_true', help="ASCII, decimal, hexadecimal, octal dump")
p.add_argument("-f","--file",dest="file",help="Read file as an input")
p.add_argument("-s","--string",dest="string",help="Read input from string")
p.add_argument("-i","--interactive",action='store_true',help="Inter interactive mode")

args = p.parse_args()

def hexlog(input):
   if args.hexdump:
      log.hexdump(input)

try:
   context.arch=args.arch

except:
   log.warn("arch is not valid")
   exit()

if args.asm and args.disasm:
   log.warn("you can not use both assemble and disassemble together")
   exit()

elif args.interactive:
   if args.asm:
      while True:
         input = raw_input('[SHELLCOLD]:# ')
         if input == '\n':
            continue
         try:
            log.info(repr(asm(str(input))))
            hexlog(asm(str(input)))
         except:
            continue

   elif args.disasm:
      while True:
         input = raw_input('[SHELLCOLD]:# ')
         if input == '\n':
            continue
         try:
            log.info(disasm(str(input)))
            hexlog(input)
         except:
            continue
elif args.asm:
   if args.file != None:
      try:
         file = open(args.file).read().replace("\n","\\n")
         log.info(repr(asm(file)))
         hexlog(asm(file))

      except:
         log.warn("file is not valid")
         exit()
   elif args.string != None:
      try:
         log.info(repr(asm(args.string)))
         hexlog(asm(args.string))
      except:
         log.warn("string is not valid")
         exit()
elif args.disasm:
   if args.file != None:
      try:
         file = open(args.file).read()
         log.info(disasm(file))
         hexlog(file)
      except:
         log.warn("file is not valid")
         exit()
   elif args.string != None:
      try:
         log.info(disasm(args.string))
         hexlog(args.string)
      except:
         log.warn("string is not valid")
         exit()
else:
   if args.file != None:
      try:
         file = open(args.file).read().replace("\n","\\n")
         hexlog(file)
      except:
         log.warn("file is not valid")
         exit()
   elif args.string != None:
      try:
         hexlog(args.string)
      except:
         log.warn("string is not valid")
         exit()
