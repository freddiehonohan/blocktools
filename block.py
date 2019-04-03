from blocktools import *
from opcode import *
from datetime import datetime
import time

class BlockHeader:
	def __init__(self, blockchain):
		self.version = uint4(blockchain)
		self.previousHash = hash32(blockchain)
		self.merkleHash = hash32(blockchain)
		self.time = uint4(blockchain)
		self.bits = uint4(blockchain)
		self.nonce = uint4(blockchain)
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

class Block:
	def __init__(self, blockchain):
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
		print ""
		print "Magic No: \t%8x" % self.magicNum
		print "Blocksize: \t", self.blocksize
		print ""
		print "#"*10 + " Block Header " + "#"*10
		self.blockHeader.toString()
		print 
		print "##### Tx Count: %d" % self.txCount
		for t in self.Txs:
			t.toString()
		print "#### end of all %d transactins" % self.txCount

class Tx:
	def __init__(self, blockchain):
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
		
	def toString(self):
		print ""
		print "="*20 + " No. %s " %self.seq + "Transaction " + "="*20
		print "Tx Version:\t %d" % self.version
		print "Inputs:\t\t %d" % self.inCount
		for i in self.inputs:
			i.toString()

		print "Outputs:\t %d" % self.outCount
		for o in self.outputs:
			o.toString()
		print "Lock Time:\t %d" % self.lockTime

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
			return hexstr
		scriptLen = int(hexstr[0:2],16)
		scriptLen *= 2
		script = hexstr[2:2+scriptLen] 
		if self.scriptLen == 2:
			print("t\Script:\t " + OPCODE_NAMES[int(hexstr[0:2],16)]+" "+OPCODE_NAMES[int(hexstr[2:4],16)])
			return hexstr
		if script[-2:] == '82': #OP_SIZE e.g. txid:bc197104ed150ffb76ed3f3824ce99b05b39e6329eb4e1d7347888ac7f68fa76
			decodedScript = hexstr[2:scriptLen]+" NONE|ANYONECANSPEND "+hexstr[scriptLen+4:]
			print "\tScript:\t " + decodedScript
			return hexstr
		print "\tScript:\t\t " + script+'\n'
		if len(hexstr) < scriptLen+2: #e.g. txid:1ddf545ccf0bf653134b2110b73fda185ca99348895900a677eed0ddb922aac3
			print " \tNon-Standard 'STRANGE' input script:\t"+hexstr
			return hexstr
		elif SIGHASH_ALL != int(hexstr[scriptLen:scriptLen+2],16): # should be 0x01
			op_codeTail = OPCODE_NAMES[int(hexstr[-2:],16)]
			if op_codeTail=="OP_CHECKMULTISIG":                         # Stack Exchange (http://archive.is/eMO5i)
				op_codeTailCount = OPCODE_NAMES[int(hexstr[-4:-2],16)]
				pubkeyCount = int(op_codeTailCount.split('_')[1])
				print str(pubkeyCount) + " "+hexstr+'\n'
				inputScriptSig=""
				try: 
				    op_code1 = OPCODE_NAMES[int(hexstr[0:2],16)]
				except KeyError: #Obselete pay to pubkey directly 
					print " \tOP_CODE key %s Error"%hexstr[0:2]
					return hexstr
				inputScriptSig+=op_code1
				curIndex = 2
				cur_opValue = hexstr[curIndex:curIndex+2]
				sigCount = 0
				while(sigCount<pubkeyCount):    # Loop until we hit PUSHDATA1 or pubkeys -1 
					inputScriptSig+=(" OP_PUSHDATA:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_SEQ:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_LENGTH:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_INT:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_LENGTH:"+str(cur_opValue))
					curIndex+=2
					sigLength = int(cur_opValue,16)*2
					sigR = hexstr[curIndex:curIndex+sigLength]
					inputScriptSig+= (" "+sigR)
					curIndex+=sigLength
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_INT:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_LENGTH:"+str(cur_opValue))
					curIndex+=2
					print inputScriptSig
					sigLength = int(cur_opValue,16)*2
					sigS = hexstr[curIndex:curIndex+sigLength]
					inputScriptSig+= (" "+sigS)
					curIndex+=sigLength
					cur_opValue = hexstr[curIndex:curIndex+2]
					if int(cur_opValue,16) == SIGHASH_ALL:
						inputScriptSig+=(' OP_SIGHASHALL:'+str(cur_opValue))
						print("Remaining hex: "+hexstr[curIndex+2:])
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					sigCount+=1
					if int(cur_opValue,16) == OP_PUSHDATA1:
						break
				inputScriptSig+=(" OP_PUSHDATA:"+str(cur_opValue))
				curIndex+=2
				if int(cur_opValue,16) == OP_PUSHDATA1:
					cur_opValue = hexstr[curIndex:curIndex+2]# next value is amount of bytes on stack
					inputScriptSig+= (" OP_INT:"+str(cur_opValue))
					curIndex+=2
					cur_opValue = hexstr[curIndex:curIndex+2]
					curOp = OPCODE_NAMES[int(cur_opValue,16)]
					inputScriptSig+= (" "+curOp+":"+str(cur_opValue))
					curIndex+=2
				else:
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_INT:"+str(cur_opValue))
					curIndex+=2
				print inputScriptSig
				for i in range(0,pubkeyCount):
					cur_opValue = hexstr[curIndex:curIndex+2]
					inputScriptSig+= (" OP_DATA:"+str(cur_opValue))
					keylen = int(cur_opValue,16)*2
					curIndex+=2
					pubkey = hexstr[curIndex:curIndex+keylen]
					inputScriptSig+= " "+pubkey
					curIndex+=keylen
					print str(i)+" "+inputScriptSig+'\n'
				inputScriptSig+=" "+op_codeTailCount+" "+op_codeTail
				print " \tMultiSig:\t "+inputScriptSig
				return hexstr
			else:
				print " \tScript op_code is not SIGHASH_ALL"
				return hexstr
		else: 
			pubkey = hexstr[2+scriptLen+2:2+scriptLen+2+66]
			print " \tInPubkey:\t "  + pubkey
#		return hexstr
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
		elif op_idx >= int('0x51',16) and op_idx <= int('0x60',16): #OP_CODE1 in {OP_1, OP_2 ... OP_16} check for tail: OP_CHECKMULTISIG
			op_codeTail = OPCODE_NAMES[int(hexstr[-2:],16)]
			if op_codeTail=="OP_CHECKMULTISIG":
				op_codeTailCount = OPCODE_NAMES[int(hexstr[-4:-2],16)] #Signature count
				pubkeyCount = int(op_codeTailCount.split('_')[1])
				pubkeys = ""
				curIndex = 2
				for i in range(0,pubkeyCount):
					keylen = int(hexstr[curIndex:curIndex+2],16)
					curIndex+=2
					pubkeys+=hexstr[curIndex:curIndex+(keylen*2)]+" "
					curIndex+=keylen*2
			print " \tMultiSig:\t " + op_code1 + " %s" % pubkeys +op_codeTailCount+" "+op_codeTail
			return hexstr
		else: #TODO extend for multi-signature parsing 
			print "\t Need to extend multi-signatuer parsing %x" % int(hexstr[0:2],16) + op_code1
			return hexstr
		
