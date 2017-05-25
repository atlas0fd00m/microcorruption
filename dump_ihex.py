#!/usr/bin/env python

import sys
import vivisect
import vivisect.cli as viv_cli
import rflib.intelhex as intelhex
#fw_s = ''' asm here '''

def processMem(mem=None, filename=None):
    if mem == None:
        mem = file(filename+'.mem').read()

    fw_l = mem.split('\n')

    names = []
    instrs = []
    segment = []
    segments = [ segment ]
    segaddrbase = [0]
    prevaddr = 0
    prevbytelen = 0

    for line in fw_l:
        line = line.strip()
        if line[:5].endswith(':'):
            # instruction or string
            addr = int(line[:4], 16)
            bytez = line[7:]
            bytezlen = len(bytez)
            #print " len: %s" % bytezlen

            if bytez.endswith('"'):
                # string
                print "STRING: " + line
                bytez = bytez[:-1] + '\x00'

            elif 40 <= bytezlen <= 59 and bytez[0] == bytez[5] == bytez[10] == ' ':
                # MEMORY line
                bytez = bytez[1:40].replace(' ','').decode('hex')

            elif bytezlen == 2:
                # MEMORY line of all NULL:
                bytez = '\0' * 16

            else:
                # line of ASM.  scraping out just the hex
                nbytes = ''
                try:
                    for bits in bytez.split(' '):
                        int(bits, 16)
                        nbytes += bits
                        #print "-=-= " + nbytes
                except:
                    pass
                bytez = nbytes.replace(' ', '')
                #print repr(bytez)
                bytez = bytez.decode('hex')

            if addr != prevaddr + prevbytelen:
                print "New Segment:  %x != %x + %x" % (addr, prevaddr, prevbytelen)
                segment = []
                segments.append(segment)
                segaddrbase.append(addr)
            #print repr(bytez)
            segment.append(bytez)
            prevbytelen = len(bytez)
            prevaddr = addr
        elif line[:6].endswith('<'):
            # symbol name, function beginning
            name = line[6:]
            name = name[:name.find('>')]
            addr = int(line[:4], 16)
            print " NAME:  %s = %x" % (name, addr)
            names.append((addr, name))


    # now let's write us some ihex!
    ih=intelhex.IntelHex()

    # ihex files are broken into different segments, which we'll use
    # when creating our vivisect workspace.
    for sidx in range(len(segments)):
        addr = segaddrbase[sidx]
        segment = segments[sidx]
        ih.puts(addr, ''.join(segment))

    # save it to a file (viv's ihex loader likes it that way)
    ih.tofile(filename, 'hex')
   
    # now on to populating our Vivisect Workspace
    # create the workspace:
    vw = viv_cli.VivCli()
    
    # make sure the ihex parser config settings are correct for msp430
    vw.config.viv.parsers.ihex.arch = 'msp430'
    
    # now load the ihex we've created
    vw.loadFromFile(filename)

    # we've loaded up the binary, but if we've discovered any names, let's apply them here.
    for addr, name in names:
        vw.makeName(addr, name)

    # now we kick off "autoanalysis"
    vw.analyze()

    # and save the workspace to file
    vw.saveWorkspace()

    # doesn't really matter that we return anything, our job is done.
    # this is for interactive work (go ipython!)
    return vw, ih, names


if __name__ == '__main__':
    filename = sys.argv[1]
    try:
        f = file(filename + '.asm', 'r')
        asm = f.read()
    except IOError, e:
        print "No assembly file found.  Please paste into STDIN and end session (Ctrl-D on linux)"
        asm = sys.stdin.read()

    vw, ih, names = processMem(asm, filename)

