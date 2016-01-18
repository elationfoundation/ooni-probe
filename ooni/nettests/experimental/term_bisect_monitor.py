from twisted.internet import protocol, defer, reactor

from ooni.nettest import NetTestCase
from ooni.utils import log
from ooni.settings import config
from ooni.utils.txscapy import ScapyProtocol, ScapyFactory
from twisted.internet.endpoints import TCP4ClientEndpoint
from ooni.errors import failureToString
from ooni.utils.net import hasRawSocketPermission

class TCPSender(protocol.Protocol):
    def __init__(self):
        self.received_data = ''
        self.sent_data = ''

    def dataReceived(self, data):
        """
        We receive data until the total amount of data received reaches that
        which we have sent. At that point we append the received data to the
        report and we fire the callback of the test template sendPayload
        function.

        This is used in pair with a TCP Echo server.

        The reason why we put the data received inside of an array is that in
        future we may want to expand this to support state and do something
        similar to what daphne does, but without the mutation.

        XXX Actually daphne will probably be refactored to be a subclass of the
        TCP Test Template.
        """
        print("RECEIVED PACKET")
        if self.payload_len:
            self.received_data += data

    def sendPayload(self, payload):
        """
        Write the payload to the wire and set the expected size of the payload
        we are to receive.

        Args:

            payload: the data to be sent on the wire.

        """
        self.payload_len = len(payload)
        self.sent_data = payload
        print("SENDING PACKET")
        self.transport.write(payload)

class TCPSenderFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return TCPSender()

class ScapyRSTListener(ScapyProtocol):
    def __init__(self, addr):
        self.addr = addr
        self.timeout = 45

        # This dict is used to store the unique hashes that allow scapy to
        # match up request with answer
        self.hr_sent_packets = {}

        # This dict is used to store a tuple with the word_list
        # for each packet and if that word list has been bisected and resent.
        self.hr_sent_wordlist = {}

        self.sent_wordlists = []

        # Words that have been tested & blocked
        self.tested_words = set()
        self.blocked_words = set()

        self.to_send = []

        # Lists containing the responses to single packets
        # Uses the packet hash as the key
        self.responses = {}

        # These are the packet pairs of sent and received packets
        self.answered_packets = []

        # These are the packets we send
        self.sent_packets = []

        # types of RST injection encountered
        self.identified_rst = set()

        self.finished = False


    def packetReceived(self, packet):
        print("packet on wire")
        # We have received a packet
        print(packet.show())
        if packet["IP"].src == self.addr:
            print("captured received packet")
            self.process_received(packet)

    def process_received(self, packet):
        log.debug("Got a packet from %s" % packet.src)
        log.debug("%s" % self.__hash__)

        packet_hash = packet.hashret()
        hr = packet.hashret()
        if hr in self.hr_sent_packets:
            answer_hr = self.hr_sent_packets[hr]
        else:
            return
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
            self.finishCleanly()
            return

    def finishCleanly(self):
        self.finished = True

    def stopSending(self):
        """Finish all testing tasks and unregister protocol.

        Initiates reporting of final results and un-register self.
        """
        result = (self.answered_packets,
                  self.sent_packets,
                  self.tested_words,
                  self.blocked_words,
                  self.identified_rst)
        #self.d.callback(result)
        self.factory.unRegisterProtocol(self)


    def get_terms(self):
        if self.to_send == []:
            return None
        terms = self.to_send.pop()
        self.sent_wordlists.append(terms)
        return " ".join(terms)


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
                    self.to_send.append(lst)
            # A single item list means that we have found a blocked item
            elif len(word_list) == 1:
                log.debug("The following term was blocked:"
                          " {0}".format(word_list[0]))
                if word_list[0] not in self.blocked_words:
                    self.blocked_words.update([word_list[0]])
        else:
            self.tested_words.update(word_list)

    def bisect(self, word_list):
        """Bisect a list of words and return both halves"""
        half = len(word_list)/2
        return [word_list[:half], word_list[half:]]


class TCPTest(NetTestCase):
    name = "Base TCP Monitoring Test"
    version = "0.1"

    requiresRoot = not hasRawSocketPermission()
    timeout = 5
    address = None
    port = None

    def _setUp(self):
        super(TCPTest, self)._setUp()

        if config.scapyFactory is None:
            log.debug("Scapy factory not set, registering it.")
            config.scapyFactory = ScapyFactory(config.advanced.interface)

        self.report['sent'] = []
        self.report['received'] = []

        self.port = 57002
        self.address = "45.79.149.108"
        self.iter_speed = 2

    def test_bisect(self):
        d1 = defer.Deferred()
        word_list = ["hello", "goodbye"]

        scapySender = ScapyRSTListener(self.address)
        config.scapyFactory.registerProtocol(scapySender)
        scapySender.all_words = word_list
        scapySender.to_send.append(word_list)

        def closeConnection(proto):
            self.report['sent'].append(proto.sent_data)
            self.report['received'].append(proto.received_data)
            proto.transport.loseConnection()
            scapySender.stopListening()
            log.debug("Closing connection")
            d1.callback(proto.received_data)

        def check_done(proto):
            # TESTING START
            print(scapySender.sent_wordlists)
            print(scapySender.tested_words)
            print(scapySender.blocked_words)
            print(scapySender.to_send)
            print(scapySender.responses)
            print(scapySender.answered_packets)
            print(scapySender.sent_packets)
            print(scapySender.identified_rst)
            print(scapySender.finished)
            # TESTING END

            if scapySender.finished:
                closeConnection(proto)
            else:
                terms = scapySender.get_terms()
                if terms:
                    proto.sendPayload(terms)
                reactor.callLater(self.iter_speed, check_done, proto)

        def timedOut(proto):
            self.report['failure'] = 'tcp_timed_out_error'
            proto.transport.loseConnection()

        def errback(failure):
            self.report['failure'] = failureToString(failure)
            d1.errback(failure)

        def connected(proto):
            log.debug("Connected to %s:%s" % (self.address, self.port))
            proto.report = self.report
            proto.deferred = d1
            terms = scapySender.get_terms()
            proto.sendPayload(terms)
            if self.timeout:
                # XXX-Twisted this logic should probably go inside of the protocol
                reactor.callLater(self.iter_speed, check_done, proto)


        point = TCP4ClientEndpoint(reactor, self.address, self.port)
        log.debug("Connecting to %s:%s" % (self.address, self.port))
        d2 = point.connect(TCPSenderFactory())
        d2.addCallback(connected)
        d2.addErrback(errback)
        return d1



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
