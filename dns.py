#!/usr/bin/python3
# -*- coding: utf-8 -*-

import struct
import socket


# RFC 1035 ....

TYPE_A = 1
TYPE_NS = 2
# TYPE_MD = 3
# TYPE_MF = 4
TYPE_CNAME = 5
TYPE_SOA = 6
# TYPE_MB = 7
TYPE_MG = 8
TYPE_MR = 9
TYPE_NULL = 10
TYPE_WKS = 11
TYPE_PTR = 12
TYPE_HINFO = 13
TYPE_MINFO = 14
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

CLASS_IN = 1
CLASS_CS = 2
CLASS_CH = 3
CLASS_HS = 4

QTYPE_AXFR = 252
QTYPE_MAILB = 253
QTYPE_MAILA = 254
QTYPE_ALL = 255

QCLASS_ALL = 255

def read_name(data, start_pos):
    idx = start_pos
    label_list = []

    while True:
        length = struct.unpack("!B", data[idx:idx+1])[0]
        idx = idx + 1
        if length > 0:
            lbl = data[idx : idx + length].decode()
            label_list.append(lbl)
            idx = idx + length
        else:
            break

    return ".".join(label_list), idx - start_pos

def build_dns_namedata(name):
    name_data = b''
    labels = name.split(".")
    for label in labels:
        lbl_bytes = label.encode()
        name_data = name_data + struct.pack("!B", len(lbl_bytes)) + lbl_bytes
    name_data = name_data + struct.pack("!B", 0)
    return name_data

class Header:
    """
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    def __init__(self):
        self.ID = 0
        self.flag = 0
        self.QDCOUNT = 0
        self.ANCOUNT = 0
        self.NSCOUNT = 0
        self.ARCOUNT = 0

        self.QR = 0
        self.OPCODE = 0
        self.AA = 0
        self.TC = 0
        self.RD = 0
        self.RA = 0
        self.RCODE = 0

    def setFlag(self, flag):
        self.flag = flag
        self.QR = flag >> 15 & 0x01
        self.OPCODE = flag >> 11 & 0x0f
        self.AA = flag >> 10 & 0x01
        self.TC = flag >> 9 & 0x01
        self.RD = flag >> 8 & 0x01
        self.RA = flag >> 7 & 0x01
        self.RCODE = flag & 0x0f

    def isQuery(self):
        if self.QR == 0:
            return True
        return False

    @staticmethod
    def generateFlags(QR, OPCODE, AA, TC, RD, RA, RCODE):
        flags = (RCODE & 0x0f) | ((RA & 0x01) << 7) | ((RD & 0x01) << 8) | ((TC & 0x01) << 9) | ((AA & 0x01) << 10) | ((OPCODE & 0X0F) << 11) | ((QR & 0x01) << 15)

        return flags

    @staticmethod
    def fromBytes(data, start_pos):
        if len(data) < start_pos + 12:
            return None, data
        
        r = struct.unpack("!6H", data[start_pos:start_pos+12])

        hdr = Header()
        hdr.ID = r[0]
        hdr.setFlag(r[1])
        hdr.QDCOUNT = r[2]
        hdr.ANCOUNT = r[3]
        hdr.NSCOUNT = r[4]
        hdr.ARCOUNT = r[5]

        return hdr, 12

    def __str__(self):
        s = "ID : {0} flag: {1}\n".format(self.ID, self.flag)
        return s

    def toBytes(self):
        data = struct.pack("!6H", self.ID, self.flag, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)
        return data


class Question:
    """
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    def __init__(self):
        self.QNAME = "" # domain name represented as a sequence of labels
        self.QTYPE = 0
        self.QCLASS = 0

    def __str__(self):
        return "QNAME : {0}\nQTYPE : {1}\nQCLASS : {2}\n".format(self.QNAME, self.QTYPE, self.QCLASS)

    @staticmethod
    def fromBytes(data, start_pos):
        label_list = []
        idx = start_pos

        qname , length = read_name(data, idx)
        idx = idx + length

        qtype, qclass = struct.unpack("!2H", data[idx: idx + 4])
        idx = idx + 4

        question = Question()
        question.QNAME = qname
        question.QTYPE = qtype
        question.QCLASS = qclass

        return question, idx - start_pos

    def toBytes(self):
        name = build_dns_namedata(self.QNAME)
        return name + struct.pack("!2H", self.QTYPE, self.QCLASS)


class ResourceRecord:
    """
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    def __init__(self):
        self.NAME = ""
        self.TYPE = 0
        self.CLASS = 0
        self.TTL = 0
        self.RDLENGTH = 0
        self.RDATA = b''

    def __str__(self):
        return "ResourceRecord\n"
    
    @staticmethod
    def fromBytes(data, start_pos):
        idx = start_pos

        name, length = read_name(data, idx)
        idx = idx + length

        rrtype, rrclass, rrttl, rdlength = struct.unpack("!2H1L1H", data[idx: idx+10])
        idx = idx + 10

        rr = ResourceRecord()
        rr.NAME = name
        rr.TYPE = rrtype
        rr.CLASS = rrclass
        rr.TTL = rrttl
        rr.RDLENGTH = rdlength
        rr.RDATA = data[idx: idx+ rdlength]

        idx = idx + rdlength

        return rr, idx - start_pos


    def setRData(self, rdata):
        self.RDATA = rdata
        self.RDLENGTH = len(rdata)

    def toBytes(self):
        data = b''
        name = build_dns_namedata(self.NAME)
        data = name + struct.pack("!2H1L1H", self.TYPE, self.CLASS, self.TTL, self.RDLENGTH) + self.RDATA
        return data



class Message:
    """
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
    """
    def __init__(self):
        self.header = Header()
        self.question = []
        self.Answer = []
        self.Authority = []
        self.Additional = []

    def __str__(self):
        hdr_str = "Header" + str(self.header)

        qstr = "Question : {0}".format(len(self.question)) + "\n"
        for q in self.question:
            qstr = qstr + str(q)

        ans_str = "Answer : {0}".format(len(self.Answer)) + "\n"
        for ans in self.Answer:
            ans_str = ans_str + str(ans)

        authority_str = "Authority : {0}".format(len(self.Authority)) + "\n"
        for a in self.Authority:            
            authority_str = authority_str + str(a)

        additional_str = "Additional : {0}".format(len(self.Additional)) + "\n"
        for a in self.Additional:
            additional_str = additional_str + str(a)

        return hdr_str + qstr + ans_str


    @staticmethod
    def fromBytes(data):
        orig_data = data
        current_pos = 0

        hdr, length = Header.fromBytes(data, current_pos)
        if hdr == None:
            return None

        current_pos = current_pos + length

        question_list = []

        for i in range(hdr.QDCOUNT):
            question, length = Question.fromBytes(data, current_pos)
            current_pos = current_pos + length
            question_list.append(question)

        answer_list = []
        for i in range(hdr.ANCOUNT):
            record, length = ResourceRecord.fromBytes(data, current_pos)
            current_pos = current_pos + length
            answer_list.append(record)
        
        authority_list = []
        for i in range(hdr.NSCOUNT):
            record, length = ResourceRecord.fromBytes(data, current_pos)
            current_pos = current_pos + length
            authority_list.append(record)

        additional_list = []
        for i in range(hdr.ARCOUNT):
            record, length = ResourceRecord.fromBytes(data, current_pos)
            current_pos = current_pos + length
            additional_list.append(record)

        msg = Message()
        msg.header = hdr
        msg.question = question_list
        msg.Answer = answer_list
        msg.Authority = authority_list
        msg.Additional = additional_list

        return msg

    def toBytes(self):
        data = self.header.toBytes()
        for q in self.question:
            data = data + q.toBytes()
        for r in self.Answer:
            data = data + r.toBytes()
        for r in self.Authority:
            data = data + r.toBytes()
        for r in self.Additional:
            data = data + r.toBytes()

        return data


class DnsServer:
    def __init__(self):
        self.dns_server_host = "dns1.trkang.pe.kr"
        self.lookup_table = []

    def appendRecord(self, NAME, TYPE, CLASS, RDATA, TTL):
        table = []
        found = False
        
        for name in self.lookup_table:
            if name["name"] == NAME:
                table = name["table"]
                found = True
                break
        
        table.append((TYPE, CLASS, RDATA, TTL))
        if not found:
            self.lookup_table.append({"name": NAME, "table":table})


    def lookupData(self, NAME, TYPE, CLASS):
        rlist = []

        for name in self.lookup_table:
            if name["name"] == NAME:
                table = name["table"]
                for v in table:
                    if v[0] == TYPE and v[1] == CLASS:
                        r = (v[2], v[3])
                        rlist.append(r)
        return rlist


    def createAnswers(self, question_list):
        answer_list = []
        result_qlist = []

        for q in question_list:
            if q.QTYPE == TYPE_PTR and q.QCLASS == CLASS_IN:
                if q.QNAME == "22.0.168.192.in-addr.arpa":
                    rr = ResourceRecord()
                    rr.NAME = q.QNAME
                    rr.TYPE = q.QTYPE
                    rr.CLASS = q.QCLASS
                    rr.TTL = 60
                    rdata = build_dns_namedata(self.dns_server_host)
                    rr.setRData(rdata)
                    answer_list.append(rr)
                    result_qlist.append(q)
            else:
                rlist = self.lookupData(q.QNAME, q.QTYPE, q.QCLASS)

                for r in rlist:
                    rr = ResourceRecord()
                    rr.NAME = q.QNAME
                    rr.TYPE = q.QTYPE
                    rr.CLASS = q.QCLASS
                    rr.setRData(r[0])
                    rr.TTL = r[1]
                    answer_list.append(rr)
                if len(rlist) > 0:
                    result_qlist.append(q)

        return result_qlist, answer_list


    def createResponse(self, req):
        res_list = []

        answer_list = []
        result_qlist = []

        if req.header.isQuery() and req.header.OPCODE == 0:
            result_qlist, answer_list = self.createAnswers(req.question)
            if len(answer_list) > 0:
                res = Message()
                res.question = result_qlist
                res.Answer = answer_list
                res.Authority = []
                res.Additional = []

                flags = Header.generateFlags(1, 0, 0, 0, 0, 0, 0)

                hdr = Header()
                hdr.ID = req.header.ID
                hdr.setFlag(flags)

                hdr.QDCOUNT = len(res.question)
                hdr.ANCOUNT = len(res.Answer)
                hdr.NSCOUNT = len(res.Authority)
                hdr.ARCOUNT = len(res.Additional)

                res.header = hdr
                res_list.append(res)

        return res_list


import socketserver
import datetime

dnsServer = DnsServer()
dnsServer.appendRecord("www.naver.com", TYPE_A, CLASS_IN, socket.inet_pton(socket.AF_INET, "192.168.0.22"), 60)
dnsServer.appendRecord("www.daum.net", TYPE_A, CLASS_IN, socket.inet_pton(socket.AF_INET, "192.168.0.23"), 60)
dnsServer.appendRecord("www.daum.net", TYPE_AAAA, CLASS_IN, socket.inet_pton(socket.AF_INET6, "fe80::4c2c:d349:ba1f:a06b"), 60)

class DnsUdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request[1]
        data = self.request[0]

        # Header - Question - Answer - Authority - Additional

        # Transaction ID : 2byte
        # Flag : 2byte
        # print("recved ", datetime.datetime.now())
        msg = Message.fromBytes(data)

        res_list = dnsServer.createResponse(msg)
        for res in res_list:
            sock.sendto(res.toBytes(), self.client_address)
            # print("sendto", datetime.datetime.now())


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53
    with socketserver.UDPServer((HOST, PORT), DnsUdpHandler) as server:
        server.serve_forever()


