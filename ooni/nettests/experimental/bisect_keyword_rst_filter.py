# -*- encoding: utf-8 -*-
#
# :authors: Arturo Filastò, Seamus Tuohy
# :licence: see LICENSE

## TODO REMOVE TESTING IMPORTS
import time
import random
from sys import getsizeof
from twisted.python import usage
from ooni.templates import scapyt
from twisted.internet import defer
from scapy.layers.inet import TCP, IP
from scapy.volatile import RandShort
from ooni.utils import log
from ooni.utils.txscapy import ScapySender
from ooni.settings import config
from scapy.all import Gen, SetGen


class UsageOptions(usage.Options):
    optParameters = [
        ['backend', 'b', '127.0.0.1:57002',
         'Test backend running TCP echo']
    ]


class KeywordFiltering(scapyt.BaseScapyTest):
    """
    This test performs...

    Usually this test should be run with a list of....
    """
    name = "RST Keyword Bisect"
    description = ("Tests for TCP RST based keyword filtering "
                   "by bisecting a list of key terms.")
    author = "Seamus Tuohy"
    version = "0.1"
    # XXX Need to implement proper PMTU detection instead of
    #     using an arbitray-ish minimum bound.
    tcp_ip_overhead = 40
    mtu = 1280

    usageOptions = UsageOptions

    inputFile = ['file', 'f', None,
                 'List of keywords to use for censorship testing']
    requiresRoot = True
    requiresTor = False

    def inputProcessor(self, filename):
        # load up the file (
        # XXX TODO mongodb

        packet_load_bounds = self.mtu  - self.tcp_ip_overhead

        test_set = []
        set_bytes = 0

        fp = open(filename)
        for x in fp.xreadlines():
            if x.startswith("#"):
                continue

            current_word = x.strip()
            word_bytes = len(current_word + " ")
            if word_bytes + set_bytes <= packet_load_bounds:
                test_set.append(current_word)
                set_bytes += word_bytes
            else:
                yield test_set
                test_set = []
                test_set.append(current_word)
                set_bytes = 0
        if test_set != []:
            yield test_set
        fp.close()

    def finishedSendReceive(self, packets):
        """
        This gets called when all packets have been sent and received.
        """
        answered, unanswered, tested, blocked = packets

        for term in blocked:
            self.report['blocked_terms'].append(term)
        for term in tested:
            self.report['tested_terms'].append(term)

        for snd, rcv in answered:
            log.debug("Writing report for scapy test")
            sent_packet = snd
            received_packet = rcv

            if not config.privacy.includeip:
                log.debug("Detected you would not like to "
                          "include your ip in the report")
                log.debug(
                    "Stripping source and destination IPs from the reports")
                sent_packet.src = '127.0.0.1'
                received_packet.dst = '127.0.0.1'

            self.report['sent_packets'].append(sent_packet)
            self.report['answered_packets'].append(received_packet)
        return packets


    def sbr(self, packet_info, word_list, timeout=None, *arg, **kw):
        """
        """
        bisectSender = BisectSender()

        config.scapyFactory.registerProtocol(bisectSender)
        log.debug("Using sending with hash %s" % bisectSender.__hash__)

        d = bisectSender.startSending(packet_info, word_list, timeout=timeout)
        d.addCallback(self.finishedSendReceive)
        return d

    @defer.inlineCallbacks
    def test_tcp_rst_keyword_filtering(self):
        """
        Places the keyword to be tested in the payload of a TCP packet.

            ## Process:
            ### Send Test Starting Packet
            ### Send Test string
            ### TODO Wait for packet to be returned (checking for directionality)
            ### Check for RST packet
            ### If any blocked, repeat with bisection

        """
        self.report['blocked_terms'] = []
        self.report['tested_terms'] = []
        backend_ip, backend_port = self.localOptions['backend'].split(':')
        word_set = self.input

        packet_info = {"ip":backend_ip,
                       "sport":4000,
                       "dport":backend_port}

        d = yield self.sbr(packet_info, word_set)

class BisectSender(ScapySender):

    def __init__(self):
        self.timeout = 45

        # This dict is used to store the unique hashes that allow scapy to
        # match up request with answer
        self.hr_sent_packets = {}

        # This dict is used to store the word_list for each packet
        self.hr_sent_wordlist = {}

        # Words that have been tested & blocked
        self.tested_words = []
        self.blocked_words = []

        # These are the packets we have received as answer to the ones we sent
        self.answered_packets = []

        # These are the packets we send
        self.sent_packets = []

    def startSending(self, packet_info, word_list, timeout=None):
        if timeout:
            self.timeout = int(timeout)
        self.all_words = word_list
        self.packet_info = packet_info
        self._start_time = time.time()
        self.d = defer.Deferred()
        self.sendBisected(word_list)
        return self.d

    def bisect(self, word_list):
        half = len(word_list)/2
        return [word_list[:half], word_list[half:]]

    def stopSending(self):
        result = (self.answered_packets,
                  self.sent_packets,
                  self.tested_words,
                  self.blocked_words)
        self.d.callback(result)
        self.factory.unRegisterProtocol(self)

    def build_packets(self, word_list):
        word_string = " ".join(word_list)
        packets = (IP(dst=self.packet_info["ip"], id=RandShort()) /
                   TCP(sport=random.randint(40000,60000), #sport=self.packet_info["sport"],
                       dport=int(self.packet_info["dport"])) /
                   word_string)
        return packets

    def sendBisected(self, word_list):
        packets = self.build_packets(word_list)

        if not isinstance(packets, Gen):
            packets = SetGen(packets)
        for packet in packets:
            hashret = packet.hashret()

            if hashret in self.hr_sent_packets:
                self.hr_sent_packets[hashret].append(packet)
            else:
                self.hr_sent_packets[hashret] = [packet]
            # Track word lists being processed as well
            # Only should be one word list per packet
            self.hr_sent_wordlist[hashret] = word_list

            self.sent_packets.append(packet)
            self.factory.send(packet)

    def processAnswer(self, packet, answer_hr):
        log.debug("Got a packet from %s" % packet.src)
        log.debug("%s" % self.__hash__)

        for i in range(len(answer_hr)):
            if packet.answers(answer_hr[i]):
                self.answered_packets.append((answer_hr[i], packet))
                del (answer_hr[i])
            break

        flags = list(packet.sprintf('%TCP.flags%'))
        packet_hash = packet.hashret()
        word_list = self.hr_sent_wordlist[packet_hash]

        if "R" in flags:
            log.debug("RST received")
            if len(word_list) > 1:
                lists = self.bisect(word_list)
                for lst in lists:
                    self.sendBisected(lst)
            elif len(word_list) == 1:
                log.debug("The following term was blocked: {0}".format(word_list[0]))
                if word_list[0] not in self.blocked_words:
                    self.blocked_words.append(word_list[0])
        else:
            self.tested_words += word_list

        all_tested = self.tested_words + self.blocked_words

        # set is acceptable because we can ignore duplicates
        # as long as they are tested at least once
        if set(all_tested) == set(self.all_words):
            log.debug("All words have been tested")
            self.stopSending()
            return
