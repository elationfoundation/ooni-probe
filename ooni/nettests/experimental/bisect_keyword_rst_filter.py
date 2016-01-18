# -*- encoding: utf-8 -*-
#
# :authors: Arturo Filastò, Seamus Tuohy
# :licence: see LICENSE

import time
import random

from twisted.python import usage
from twisted.internet import defer
from scapy.layers.inet import TCP, IP
from scapy.volatile import RandShort
from scapy.all import Gen, SetGen

from ooni.utils import log
from ooni.utils.txscapy import ScapySender
from ooni.settings import config
from ooni.templates import scapyt


class UsageOptions(usage.Options):
    optParameters = [
        ['backend', 'b', '127.0.0.1:57002',
         'Test backend running TCP echo']]


class TermRstFilteringBisect(scapyt.BaseScapyTest):
    """Performs testing of term based RST injection over a set
    of terms. This test uses list bisection to quickly test
    large sets of terms while still being able to identify
    which specific terms are leading to blocking.

    Usually this test should be run with a larger list of uncensored
    terms in order to identify newly censored terms. If this
    test is passed a list that mainly contains censored words it
    will end up doing more work than if each word were tested
    individually.

    This test sends a raw TCP packet with possibly blocked
    keywords within it. As such, keyword based detection that
    checks for keywords at a specific point in the connection
    (e.g. after a handshake), within a specific type of request
    (e.g. during a GET request) will not be detected.

    Initial RST term matching enumeration testing should be
    conducted with a known filtered term to identify the places
    and conditions under which term matching occurs. Once that
    has been identified this test can be modified to test against
    the conditions identified.
    """
    name = "Term RST Filtering - Bisect"
    description = ("Tests for TCP RST based term filtering "
                   "by bisecting a list of key terms.")
    author = "Seamus Tuohy"
    version = "0.1"
    # TODO Need to implement proper PMTU detection instead of
    #      using the below to create an assumed network boundry
    tcp_ip_overhead = 40
    mtu = 1280

    usageOptions = UsageOptions
    inputFile = ['file', 'f', None,
                 'List of keywords to use for censorship testing']
    requiresRoot = True
    requiresTor = False
    requiredOptions = ['file']
    requiredTestHelpers = {'backend': 'tcp-directionality'}


    def inputProcessor(self, filename):
        # Set max packet size boundry
        packet_load_bounds = self.mtu - self.tcp_ip_overhead
        test_set = []
        set_bytes = 0

        fp = open(filename)
        for x in fp.xreadlines():
            # Don't read commented out lines
            if x.startswith("#"):
                continue
            # Add words to the test set until it reaches
            # the max packet size boundry
            current_word = x.strip()
            word_bytes = len(current_word + " ")
            if word_bytes + set_bytes <= packet_load_bounds:
                test_set.append(current_word)
                set_bytes += word_bytes
            else:
                yield test_set
                # Start new test set with word that went
                # over the packet size boundry
                test_set = []
                test_set.append(current_word)
                set_bytes = 0
        # Send out the final test set.
        if test_set != []:
            yield test_set
        fp.close()

    def finishedSendReceive(self, packets):
        """
        This gets called when all packets have been sent and received.

        Args:
            packets (tuple): A tuple containing five objects
                - [0] answered packets (list) Packets that were answered
                - [1] sent packets (list) Packets that were sent.
                - [2] tested terms (set) Strings that were tested.
                - [3] blocked terms (set) Strings that were found to be blocked.
                - [4] identified rst (set) Types of RST injection identified.
        """
        answered, unanswered, tested, blocked, id_rst = packets

        # Add terms to report
        for term in blocked:
            self.report['blocked_terms'].append(term)
        for term in tested:
            self.report['tested_terms'].append(term)

        for rst_type in id_rst:
            self.report['rst_injection_types'].append(rst_type)

        for snd, rcv in answered:
            log.debug("Writing report for RST bisect test")
            sent_packet = snd
            received_packet = rcv

            # Remove IP address' if privacy set
            if not config.privacy.includeip:
                log.debug("Detected you would not like to "
                          "include your ip in the report")
                log.debug("Stripping source and destination "
                          "IPs from the reports")
                sent_packet.src = '127.0.0.1'
                received_packet.dst = '127.0.0.1'

            # Add packets to report
            self.report['sent_packets'].append(sent_packet)
            self.report['answered_packets'].append(received_packet)
        return packets

    def bisect_sendrecv(self, packet_info, word_list, timeout=None):
        """ Sender and receiver for lists to be bisected.

        Based upon BaseScapyTest.sr from scapyt.py.

        Wrapper around scapy.sendrecv.sr for sending and receiving of packets
        at layer 3.

        """
        bisectSender = BisectSender()

        config.scapyFactory.registerProtocol(bisectSender)
        log.debug("Using sender with hash %s" % bisectSender.__hash__)

        d = bisectSender.startSending(packet_info, word_list, timeout=timeout)
        d.addCallback(self.finishedSendReceive)
        return d

    @defer.inlineCallbacks
    def test_tcp_rst_term_filtering(self):
        """ Do iterative TCP RST injection tests against a term list using
        bisection to limit the number of TCP packets sent.
        """
        self.report['blocked_terms'] = []
        self.report['tested_terms'] = []
        self.report['rst_injection_types'] = []
        backend_ip, backend_port = self.localOptions['backend'].split(':')
        word_set = self.input

        packet_info = {"ip":backend_ip,
                       "sport":4000, # TODO Currently not used
                       "dport":backend_port}
        yield self.bisect_sendrecv(packet_info, word_set)


class BisectSender(ScapySender):
    """
    """

    def __init__(self):
        self.timeout = 45

        # This dict is used to store the unique hashes that allow scapy to
        # match up request with answer
        self.hr_sent_packets = {}

        # This dict is used to store a tuple with the word_list
        # for each packet and if that word list has been bisected and resent.
        self.hr_sent_wordlist = {}

        # Words that have been tested & blocked
        self.tested_words = set()
        self.blocked_words = set()

        # Lists containing the responses to single packets
        # Uses the packet hash as the key
        self.responses = {}

        # These are the packet pairs of sent and received packets
        self.answered_packets = []

        # These are the packets we send
        self.sent_packets = []

        # types of RST injection encountered
        self.identified_rst = set()

    def startSending(self, packet_info, word_list, timeout=None):
        """ Set properties and start sending

        Args:
            packet_info (dict): A dict containing the ip, source port, and
                destination port of the packet to be sent.
                    - ip (string): IP address to send packets to.
                    - sport (int): The source port for sent packets.
                    - dport (int): The destination port of the packets.
            word_list (list): A list of strings to be sent within each packet.
                The total byte lenth of these words joined with a single space
                between them should be able to fit within a single TCP packet.
            timeout (int): The number of seconds to wait for a response until
                 the sender shoud timeout.

        """
        if timeout:
            self.timeout = int(timeout)
        self.all_words = word_list
        self.packet_info = packet_info
        self._start_time = time.time()

        self.d = defer.Deferred()
        self.sendBisected(word_list)
        return self.d

    def bisect(self, word_list):
        """Bisect a list of words and return both halves"""
        half = len(word_list)/2
        return [word_list[:half], word_list[half:]]

    def stopSending(self):
        """Finish all testing tasks and unregister protocol.

        Initiates reporting of final results and un-register self.
        """
        result = (self.answered_packets,
                  self.sent_packets,
                  self.tested_words,
                  self.blocked_words,
                  self.identified_rst)
        self.d.callback(result)
        self.factory.unRegisterProtocol(self)

    def build_packets(self, word_list):
        """Build a TCP/IP packet from a word list"""
        word_string = " ".join(word_list)
        # Currently picks a random source port for each packet
        # instead of respecting the source port from packet_info
        # TODO make a decision about using random or selected
        # sport=self.packet_info["sport"],
        packets = (IP(dst=self.packet_info["ip"], id=RandShort()) /
                   TCP(sport=random.randint(40000,60000),
                       dport=int(self.packet_info["dport"])) /
                   word_string)
        return packets

    def sendBisected(self, word_list):
        """Send a word list within a TCP packets.

        Args:
            word_list (list): A list of strings to be sent within each packet.
        """
        packets = self.build_packets(word_list)

        if not isinstance(packets, Gen):
            packets = SetGen(packets)

        for packet in packets:
            # TODO DELETE DEBUG BELOW
            log.debug("Sending packet with data: {0}".format(packet.getlayer("Raw").load))

            # Store hash so we can ID response
            hashret = packet.hashret()
            if hashret in self.hr_sent_packets:
                self.hr_sent_packets[hashret].append(packet)
            else:
                self.hr_sent_packets[hashret] = [packet]

            # TODO DELETE DEBUG BELOW
            log.debug("packet hash: {0}".format(hashret))

            # Mark that word list is sent, and not yet bisected
            self.hr_sent_wordlist[hashret] = (word_list, False)
            self.sent_packets.append(packet)
            # Send packets through the TermFilteringBisect factory's
            # send() method which is inhereted from scapyt.BaseScapyTest
            self.factory.send(packet)

    def processAnswer(self, packet, answer_hr):
        """Process packet to check if RST occured.

        Currently checks against the following set of RST detectors:
        - rst_seq_data: Detects when a RST packet is sent after
            the helper response.
        - data_seq_rst: Detects when a RST packet is followed by
            the helper response.
        - data_seq_change: Detects the receipt of back to back RST
            packets with increasing sequence numbers.
        - rst_ack_change: Detects sets of RST's with ACK numbers
            differ from each other and are not in the range of
            sequence numbers of test packet.

        Detection methods based upon "Detecting Forged TCP Reset Packets"
        by Weaver, Sommer, and Paxson
        http://www.icir.org/vern/papers/reset-injection.ndss09.pdf

        Args:
            packet (): A packet that has been received in response
                to one of the sent packets.
            answer_hr (list): The list of unique hashes of sent packets
                              that lead to this response.
        """
        log.debug("Got a packet from %s" % packet.src)
        log.debug("%s" % self.__hash__)

        packet_hash = packet.hashret()
        # Move sent packet from sent to answered dicts
        for i in range(len(answer_hr)):
            if packet.answers(answer_hr[i]):
                if packet_hash in self.responses:
                    self.responses[packet_hash].append(packet)
                else:
                    self.responses[packet_hash] = [packet]
                self.answered_packets.append((answer_hr[i], packet))
            break

        self.run_rst_tests(packet_hash)

        all_tested = self.tested_words.union(self.blocked_words)

        # set is acceptable because we can ignore duplicates
        # as long as they are tested at least once
        if set(all_tested) == set(self.all_words):
            log.debug("All words have been tested")
            self.stopSending()
            return

    def run_rst_tests(self, packet_hash):
        """Check for RST injection and bisect if found.

        Args:
             packet_hash (str): the unique hash of the responses to
                                test.
        """
        word_list, bisected = self.hr_sent_wordlist[packet_hash]
        packet_list = self.responses[packet_hash]
        results = []
        detected = False
        for detector in [RstSeqData, DataSeqRst,
                         DataSeqChange, RstAckChange]:
            test = detector(packet_list)
            if test.detected:
                detected = True
                results.append(test.name)

        # Send bisected or update tested list
        if detected and not bisected:
            log.debug("RST blocking detected: Bisecting.")
            self.identified_rst.update(results)
            if len(word_list) > 1:
                lists = self.bisect(word_list)
                for lst in lists:
                    self.sendBisected(lst)
            # A single item list means that we have found a blocked item
            elif len(word_list) == 1:
                log.debug("The following term was blocked:"
                          " {0}".format(word_list[0]))
                if word_list[0] not in self.blocked_words:
                    self.blocked_words.update([word_list[0]])
        else:
            self.tested_words.update(word_list)


class RstDetector(object):
    def __init__(self, packet_list):
        self.detected = False
        self.packet_list = packet_list
        self.detect()

    @classmethod
    def has_rst(self, packet):
        flags = list(packet.sprintf('%TCP.flags%'))
        if "R" in flags:
            return True

    def detect(self):
        if self.has_rst:
            self.detected = True


class RstSeqData(RstDetector):
    """Detects when a RST packet is sent after the helper response.

    #http://www.icir.org/vern/papers/reset-injection.ndss09.pdf#page=4
    """
    def __init__(self, packet_list):
        self.name = "rst seq data"
        super(RstSeqData, self).__init__(packet_list)

    def detect(self):
        if len(self.packet_list) < 2:
            self.detected = False
            return
        helper_found = False
        for packet in self.packet_list:
            if self.has_rst(packet) and helper_found == True:
                self.detected = True
                return


class DataSeqRst(RstDetector):
    """Detects when a RST packet is followed by the helper response.

    #http://www.icir.org/vern/papers/reset-injection.ndss09.pdf#page=4
    """
    def __init__(self, packet_list):
        self.name = "data seq rst "
        super(DataSeqRst, self).__init__(packet_list)

    def detect(self):
        if len(self.packet_list) < 2:
            self.detected = False
            return
        rst_found = False
        for packet in self.packet_list:
            if not self.has_rst(packet) and rst_found == True:
                self.detected = True
                return


class DataSeqChange(RstDetector):
    """Detects the receipt of back to back RST packets
    with increasing sequence numbers.

    #http://www.icir.org/vern/papers/reset-injection.ndss09.pdf#page=5
    """
    def __init__(self, packet_list):
        self.name = "data seq change"
        super(DataSeqChange, self).__init__(packet_list)

    def detect(self):
        if len(self.packet_list) < 2:
            self.detected = False
            return
        rst_seq = None
        for packet in self.packet_list:
            if self.has_rst(packet):
                curr_seq = int(packet.sprintf('%TCP.seq%'))
                if not rst_seq:
                    rst_seq = curr_seq
                else:
                    if curr_seq > rst_seq:
                        self.detected = True
                        return


class RstAckChange(RstDetector):
    """Detects sets of RST's with ACK numbers differ from each other
    and are not in the range of sequence numbers of test packet.

    #http://www.icir.org/vern/papers/reset-injection.ndss09.pdf#page=5
    """

    def __init__(self, packet_list):
        self.name = "rst ack change"
        super(RstAckChange, self).__init__(packet_list)

    def detect(self):
        if len(self.packet_list) < 2:
            self.detected = False
            return
        rst_ack = None
        for packet in self.packet_list:
            if self.has_rst(packet):
                curr_ack = int(packet.sprintf('%TCP.ack%'))
                if not rst_ack:
                    rst_ack = curr_ack
                else:
                    if curr_ack > rst_ack:
                        self.detected = True
                        return
