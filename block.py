from blocktools import *
from opcode import *
from datetime import datetime
from hashlib import sha256
from binascii import hexlify
import time,sys

class BlockHeader:
    def __init__(self, blockchain):
        headerStart = blockchain.tell()
        self.version = uint4(blockchain)
        self.previousHash = hash32(blockchain)
        self.merkleHash = hash32(blockchain)
        self.time = uint4(blockchain)
        self.bits = uint4(blockchain)
        self.nonce = uint4(blockchain)
        headerEnd = blockchain.tell()
        blockchain.seek(headerStart)
        self.fullHeader = blockchain.read(headerEnd-headerStart)
    def toString(self):
        print "Version:\t %d" % self.version
        print "Previous Hash\t %s" % hashStr(self.previousHash)
        print "Merkle Root\t %s" % hashStr(self.merkleHash)
        print "Time stamp\t "+ self.decodeTime(self.time)
        print "Difficulty\t %d" % self.bits
        print "Nonce\t\t %s" % self.nonce
    def decodeTime(self, time):
        utc_time = datetime.utcfromtimestamp(time)
        return utc_time.strftime("%Y-%m-%d %H:%M:%S.%f+00:00 (UTC)")
    def calculateBlockHash(self):
        return sha256(sha256(self.fullHeader).digest()).digest()[::-1].encode('hex') # Block hash calculation (Stack Exchange: http://archive.is/Id8vn)

class Block:
    def __init__(self, blockchain):
        self.fileOffset = blockchain.tell()
        self.continueParsing = True
        self.magicNum = 0
        self.blocksize = 0
        self.blockheader = ''
        self.txCount = 0
        self.Txs = []

        if self.hasLength(blockchain, 8):	
            self.magicNum = uint4(blockchain)
            self.blocksize = uint4(blockchain)
        else:
            self.continueParsing = False
            return
        
        if self.hasLength(blockchain, self.blocksize):
            self.setHeader(blockchain)
            self.blockHash = self.blockHeader.calculateBlockHash()
            self.txCount = varint(blockchain)
            self.Txs = []

            for i in range(0, self.txCount):
                tx = Tx(blockchain)
                tx.seq = i 
                self.Txs.append(tx)
        else:
            self.continueParsing = False
                        

    def continueParsing(self):
        return self.continueParsing

    def getBlocksize(self):
        return self.blocksize

    def hasLength(self, blockchain, size):
        curPos = blockchain.tell()
        blockchain.seek(0, 2)
        
        fileSize = blockchain.tell()
        blockchain.seek(curPos)

        tempBlockSize = fileSize - curPos
#		print "tempBlockSize \t %d" % tempBlockSize
        if tempBlockSize < size:
            return False
        return True

    def setHeader(self, blockchain):
        self.blockHeader = BlockHeader(blockchain)

    def toString(self):
        print "Block Hash: "+self.blockHash
        print "Magic No: \t%8x" % self.magicNum
        print "Blocksize: \t", self.blocksize
        print ""
        print "#"*10 + " Block Header " + "#"*10
        self.blockHeader.toString()
        print 
        print "##### Tx Count: %d" % self.txCount
        for t in self.Txs:
            print "Block file offset: "+str(self.fileOffset)
            t.toString()
        print "#### end of all %d transactins" % self.txCount

class Tx:
    def __init__(self, blockchain):
        txStart = blockchain.tell()
        self.version = uint4(blockchain)
        self.inCount = varint(blockchain)
        self.inputs = []
        self.seq = 1
        for i in range(0, self.inCount):
            input = txInput(blockchain)
            self.inputs.append(input)
        self.outCount = varint(blockchain)
        self.outputs = []
        if self.outCount > 0:
            for i in range(0, self.outCount):
                output = txOutput(blockchain)
                self.outputs.append(output)	
        self.lockTime = uint4(blockchain)
        # TxID calculation (Stack Exchange: http://archive.is/kqVZf)
        self.txLength = blockchain.tell()-txStart
        blockchain.seek(txStart)
        txdata = hexlify(blockchain.read(self.txLength)).decode('hex')
        #print "Warning: this code only tested on a little-endian x86_64 arch"
        txhash = sha256(sha256(txdata).digest()).digest()
        self.txid = txhash[::-1].encode('hex_codec')
        
    def toString(self):
        print "TXID: "+self.txid
        print "="*20 + " No. %s " %self.seq + "Transaction " + "="*20
        print "Tx Version:\t %d" % self.version
        print "Inputs:\t\t %d" % self.inCount
        for i in self.inputs:
            i.toString()

        print "Outputs:\t %d" % self.outCount
        for o in self.outputs:
            o.toString()
        print "Lock Time:\t %d" % self.lockTime

def checkOpCode(value):
    if value=='01':
        return "OP_SIGHASH_ALL"
    try: 
        op_code = OPCODE_NAMES[int(value,16)]
    except KeyError:
        op_code = "OP"
    return op_code        

class txInput:
    def __init__(self, blockchain):
        self.prevhash = hash32(blockchain)
        self.txOutId = uint4(blockchain)
        self.scriptLen = varint(blockchain)
        self.scriptSig = blockchain.read(self.scriptLen)
        self.seqNo = uint4(blockchain)

    def toString(self):
#		print "\tPrev. Tx Hash:\t %s" % hashStr(self.prevhash)
        print "\tTx Out Index:\t %s" % self.decodeOutIdx(self.txOutId)
        print "\tScript Length:\t %d" % self.scriptLen
#		print "\tScriptSig:\t %s" % 
        self.decodeScriptSig(self.scriptSig)
        print "\tSequence:\t %8x" % self.seqNo
    def decodeScriptSig(self,data):
        hexstr = hashStr(data)
        if 0xffffffff == self.txOutId: #Coinbase
            return
        scriptLen = int(hexstr[0:2],16)
        scriptLen *= 2
        script = hexstr[2:2+scriptLen]
        scriptStack=[]
        if self.scriptLen == 2:
            print("t\Script:\t " + OPCODE_NAMES[int(hexstr[0:2],16)]+" "+OPCODE_NAMES[int(hexstr[2:4],16)])
            return
        if script[-2:] == '82': #OP_SIZE e.g. txid:bc197104ed150ffb76ed3f3824ce99b05b39e6329eb4e1d7347888ac7f68fa76
            decodedScript = hexstr[2:scriptLen]+" NONE|ANYONECANSPEND "+hexstr[scriptLen+4:]
            print "\tScript:\t " + decodedScript
            return
        print "\tScript:\t\t " + script+'\n'
        print hexstr
        if len(hexstr) < scriptLen+2: #e.g. txid:1ddf545ccf0bf653134b2110b73fda185ca99348895900a677eed0ddb922aac3
            print " \tNon-Standard 'STRANGE' input script:\t"+hexstr
            return # c9728b88e6e6e5fd8c87c5cf229175d3987dd95c19dabcba58a4c0ff0860e561
        elif SIGHASH_ALL != int(hexstr[scriptLen:scriptLen+2],16): # should be 0x01
            if int(hexstr[-2:],16) == SIGHASH_ALL:
                curIndex = len(hexstr)-2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                if int(cur_opValue,16)==SIGHASH_ALL:
                    # go back 32 bytes and check for sig length == 32, if not siglength = 33
                    for i in range(0,2):
                        if(hexstr[curIndex-64-2:curIndex-64]=='20'):
                            sigLength = 32
                        else:
                            sigLength = 33
                        curIndex-=sigLength*2
                        sig = hexstr[curIndex:curIndex+sigLength*2] #
                        scriptStack.append(sig)
                        curIndex-=2
                        cur_opValue=hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_LENGTH:"+cur_opValue)
                        curIndex-=2
                        cur_opValue=hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_INT:"+cur_opValue)

                curIndex-=2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append("OP_LENGTH:"+cur_opValue)
                curIndex-=2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append("OP_SEQ:"+cur_opValue)
                curIndex-=2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append("OP_PUSHDATA:"+cur_opValue)
                try: 
                    op_code1 = OPCODE_NAMES[int(hexstr[0:2],16)]
                except KeyError: #Obselete pay to pubkey directly 
                    print " \tOP_CODE key %s Error"%hexstr[0:2]+" "+hexstr
                    #sys.exit(-1)
                    return
                scriptStack.append(op_code1)
                print " \tScriptSig:\t "+" ".join(scriptStack[::-1])
                return
            else:
                op_codeTail = OPCODE_NAMES[int(hexstr[-2:],16)]
                if op_codeTail=="OP_CHECKMULTISIG":                         # Stack Exchange (http://archive.is/eMO5i)
                    scriptStack = []
                    scriptStack.append(op_codeTail)
                    op_codeTailCount = OPCODE_NAMES[int(hexstr[-4:-2],16)]
                    scriptStack.append(op_codeTailCount)
                    pubkeyCount = int(op_codeTailCount.split('_')[1])
                    curIndex = len(hexstr)-4
                    for i in range(0,pubkeyCount):
                        # try compressed first i.e. 0x02, 0x03
                        savedStartIndex=curIndex
                        curIndex -=64
                        k = hexstr[curIndex:curIndex+64]
                        curIndex -= 2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        print cur_opValue
                        if cur_opValue == '02' or cur_opValue == '03': # key is compressed 32 bytes
                            scriptStack.append(k)
                            scriptStack.append('OP_INT:'+cur_opValue)
                            curIndex -= 2
                            cur_opValue = hexstr[curIndex:curIndex+2]
                            scriptStack.append('OP_LENGTH:'+cur_opValue)
                        else:
                            curIndex = savedStartIndex-128
                            k = hexstr[curIndex:curIndex+64]
                            curIndex -= 2
                            cur_opValue = hexstr[curIndex:curIndex+2]
                            if cur_opValue == '04': # key is uncompressed 64 bytes
                                scriptStack.append(k)
                                scriptStack.append('OP_INT:'+cur_opValue)
                                curIndex -= 2
                                cur_opValue = hexstr[curIndex:curIndex+2]
                                scriptStack.append('OP_LENGTH:'+cur_opValue)
                            else:
                                print("Unknown error parsing multi-sig input: "+hexstr)
                                #sys.exit(-1)
                                return
                    curIndex-=2
                    cur_opValue = hexstr[curIndex:curIndex+2]
                    op_codeSigCount = OPCODE_NAMES[int(cur_opValue,16)]
                    scriptStack.append(op_codeSigCount)
                    reqSigs = int(op_codeSigCount.split('_')[1])
                    curIndex-=2
                    cur_opValue = hexstr[curIndex:curIndex+2]
                    scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                    curIndex-=2
                    cur_opValue = hexstr[curIndex:curIndex+2]
                    scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                    sigCount=0
                    while sigCount<reqSigs:     #https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
                        curIndex-=2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                        if int(cur_opValue,16)==SIGHASH_ALL:
                            # go back 32 bytes and check for sig length == 32, if not siglength = 33
                            for i in range(0,2):
                                if(hexstr[curIndex-64-2:curIndex-64]=='20'):
                                    sigLength = 32
                                else:
                                    sigLength = 33
                                curIndex-=sigLength*2
                                sig = hexstr[curIndex:curIndex+sigLength*2] #
                                scriptStack.append(sig)
                                curIndex-=2
                                cur_opValue=hexstr[curIndex:curIndex+2]
                                scriptStack.append("OP_LENGTH:"+cur_opValue)
                                curIndex-=2
                                cur_opValue=hexstr[curIndex:curIndex+2]
                                scriptStack.append("OP_INT:"+cur_opValue)

                        curIndex-=2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_LENGTH:"+cur_opValue)
                        curIndex-=2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_SEQ:"+cur_opValue)
                        curIndex-=2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_PUSHDATA:"+cur_opValue)
                        sigCount+=1
                    try: 
                        op_code1 = OPCODE_NAMES[int(hexstr[0:2],16)]
                    except KeyError: #Obselete pay to pubkey directly 
                        print " \tOP_CODE key %s Error"%hexstr[0:2]+" "+hexstr
                        #sys.exit(-1)
                        return
                    scriptStack.append(op_code1)
                    print " \tMultiSig:\t "+" ".join(scriptStack[::-1])
                    #sys.exit(-1)
                else:
                    if(op_codeTail=="OP_ROLL"):
                        print "OP_ROLL"
                        scriptStack.append(op_codeTail)
                    elif(op_codeTail=="OP_EQUAL"):
                        print "OP_EQUAL"
                        curIndex = len(hexstr)-2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                        for i in range(0,3):
                            curIndex-=2
                            cur_opValue = hexstr[curIndex:curIndex+2]
                            scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                        curIndex -=2
                        # go back 32 bytes and check for sig length == 32, if not siglength = 33
                        #for i in range(0,2):
                            #print "DSFFDSSDF"+hexstr[curIndex-64-2:curIndex-64]
                        if(hexstr[curIndex-64-2:curIndex-64]=='20'):
                            sigLength = 32
                        else:
                            sigLength = 33
                        curIndex-=sigLength*2
                        sig = hexstr[curIndex:curIndex+sigLength*2] #
                        scriptStack.append(sig)
                        curIndex-=2
                        cur_opValue=hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_LENGTH:"+cur_opValue)
                        curIndex-=2
                        cur_opValue=hexstr[curIndex:curIndex+2]
                        scriptStack.append("OP_INT:"+cur_opValue)
                        curIndex-=2
                        cur_opValue = hexstr[curIndex:curIndex+2]
                        scriptStack.append(checkOpCode(cur_opValue)+":"+cur_opValue)
                        print " \tOP_EQUAL, DROP:\t "+" ".join(scriptStack[::-1])

                    else:
                        print " \tScript op_code is not SIGHASH_ALL "+hexstr
                        print "Tail: "+op_codeTail
                        #sys.exit(-1)
                    return
        else:
            scriptStack=[]
            curIndex = 2+scriptLen
            cur_opValue = hexstr[curIndex:curIndex+2]
            if(int(cur_opValue,16) == OP_PUSHDATA2):
                scriptStack.append("OP_PUSHDATA2:"+cur_opValue)
                curIndex+=2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append("OP_SEQ:"+cur_opValue)
                curIndex+=2
                cur_opValue = hexstr[curIndex:curIndex+2]
                scriptStack.append("OP_LENGTH:"+cur_opValue)
                curIndex+=2
                dataLen = int(cur_opValue,16)*2
                scriptStack.append(hexstr[curIndex:curIndex+dataLen])
                print " \tMultiSig:\t "+" ".join(scriptStack)
                sys.exit(1)
                
            pubkey = hexstr[2+scriptLen+2:2+scriptLen+2+66]
            print " \tInPubkey:\t "  + pubkey

    def decodeOutIdx(self,idx):
        s = ""
        if(idx == 0xffffffff):
            s = " Coinbase with special index"
            print "\tCoinbase Text:\t %s" % hashStr(self.prevhash).decode("utf-8")
        else: 
            print "\tPrev. Tx Hash:\t %s" % hashStr(self.prevhash)
        return "%8x"%idx + s 
        
class txOutput:
    def __init__(self, blockchain):	
        self.value = uint8(blockchain)
        self.scriptLen = varint(blockchain)
        self.pubkey = blockchain.read(self.scriptLen)

    def toString(self):
        print "\tValue:\t\t %d" % self.value + " Satoshi"
        print "\tScript Len:\t %d" % self.scriptLen
        print "\tScriptPubkey:\t %s" % self.decodeScriptPubkey(self.pubkey)
    def decodeScriptPubkey(self,data):
        hexstr = hashStr(data)
        op_idx = int(hexstr[0:2],16)
        try: 
            op_code1 = OPCODE_NAMES[op_idx]
        except KeyError: #Obselete pay to pubkey directly 
            print " \tOP_CODE %d is probably obselete pay to address"
            keylen = op_idx
            op_codeTail = OPCODE_NAMES[int(hexstr[2+keylen*2:2+keylen*2+2],16)]
            print " \tPubkey OP_CODE:\t " "None " + "Bytes:%d " % keylen +\
                    "tail_op_code:" +  op_codeTail + " " 
            print "\tPure Pubkey:\t   %s" % hexstr[2:2+keylen*2]
            return hexstr
        if op_code1 == "OP_DUP":  #P2PKHA pay to pubkey hash mode
             op_code2 = OPCODE_NAMES[int(hexstr[2:4],16)] + " "
             keylen = int(hexstr[4:6],16)
             op_codeTail2nd = OPCODE_NAMES[int(hexstr[6+keylen*2:6+keylen*2+2],16)]
             op_codeTailLast = OPCODE_NAMES[int(hexstr[6+keylen*2+2:6+keylen*2+4],16)]
             print " \tPubkey OP_CODE:\t " + op_code1 + " " + op_code2 + " " + "Bytes:%d " % keylen +\
                    "tail_op_code:" +  op_codeTail2nd + " " + op_codeTailLast
             print "\tPubkeyHash:\t       %s" % hexstr[6:6+keylen*2]
             return hexstr	
        elif op_code1 == "OP_HASH160": #P2SHA pay to script hash 
            keylen = int(hexstr[2:4],16) 
            op_codeTail = OPCODE_NAMES[int(hexstr[4+keylen*2:4+keylen*2+2],16)]
            print " \tPubkey OP_CODE:\t " + op_code1 + " " + " " + "Bytes:%d " % keylen +\
                    "tail_op_code:" +  op_codeTail + " " 
            print "\tPure Pubkey:\t     %s" % hexstr[4:4+keylen*2]
            return hexstr
        elif op_code1 == "OP_RETURN": #OP_RETURN
            print " \tOP_CODE:\t " + op_code1 + " " + " %s" % hexstr[2:]
            return hexstr
        elif OPCODE_NAMES[int(hexstr[-2:],16)]=="OP_CHECKMULTISIG":#OP_CHECKMULTISIG
            op_codeTail = "OP_CHECKMULTISIG"
            op_codeTailCount = OPCODE_NAMES[int(hexstr[-4:-2],16)] #Signature count
            pubkeyCount = int(op_codeTailCount.split('_')[1])
            pubkeys = ""
            curIndex = 2
            for i in range(0,pubkeyCount):
                keylen = int(hexstr[curIndex:curIndex+2],16)
                curIndex+=2
                pubkeys+=hexstr[curIndex:curIndex+(keylen*2)]+" "
                curIndex+=keylen*2
            print " \tMultiSig:\t " + op_code1 + " %s" % pubkeys + op_codeTailCount+" "+op_codeTail
            return hexstr
        else: #TODO extend for multi-signature parsing 
            print "\t Need to extend parsing %x" % int(hexstr[0:2],16) + op_code1
            return hexstr
