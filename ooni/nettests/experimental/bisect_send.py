# -*- encoding: utf-8 -*-
#
# :licence: see LICENSE

from ooni.utils import log
from ooni.templates import tcpt
from twisted.internet import defer
from twisted.python import usage

from types import ListType

# TODO REMOVE INSPECT
import inspect

class PacketDataBisector(object):

    def __init__(self, filename, max_byte_length=1240):
        log.debug("MY ID={0}".format(id(self)))
        for i in range(10):
            print(inspect.stack()[i])
        #raise NotImplementedError()
        #log.debug("MY NAME={0}".format(self.__name__))
        self.max_byte_length = max_byte_length
        self.file_pointer = open(filename)
        self.untested = []
        self.to_bisect = []
        self.bisected = []

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_val, trace):
        try:
           self.file_pointer.close()
        except AttributeError:
           log.debug('Packet data bisector could not close file pointer.')

    @property
    def empty(self):
        """I'm the 'empty' property."""
        all_lists = [self.to_bisect, self.untested, self.bisected]
        if any(cur_list != [] for cur_list in all_lists):
            return False
        else:
            return True

    def __iter__(self):
        log.debug("ITER ID={0}".format(id(self)))
        return self

    def next(self):
        log.debug("NEXT ID={0}".format(id(self)))
        if self.to_bisect == [] and self.bisected == []:
            try:
                return self.build_data()
            except IndexError:
                # all text objects are empty if this is raised
                raise StopIteration
        else:
            return self.bisect()

    def clean_line(self, line):
        """Cleans a line for use"""
        # Don't read commented out lines
        if line.startswith("#"):
            return None
        current_term = line.strip()
        return current_term

    def seed_untested(self):
        """Seed untested with a single line of text

        Empty lines will end the object from iterating.
        """
        seed_word = None
        while seed_word is None:
            seed_word = self.clean_line(self.file_pointer.readline())
        if seed_word == "":
            raise IndexError
        self.untested.append(seed_word)

    def build_data(self):
        """Build a chunk of data"""
        # Seed untested with a single term if empty
        # If there are no lines left this raises and ends iteration
        if self.untested == []:
            self.seed_untested()

        new_data = []
        set_bytes = 0
        while self.untested != []:
            #log.debug("{0} Bytes".format(set_bytes))
            # Seed untested with a new line every iteration
            try:
                self.seed_untested()
            except IndexError:
                log.debug("End of file reached within packet build")
            #log.debug("Self.untested = {0}".format(self.untested))
            current_word = self.untested.pop(0)
            word_bytes = len(current_word + "|")
            if word_bytes + set_bytes <= self.max_byte_length:
                #log.debug("Adding term \"{0}\" to packet".format(current_word))
                new_data.append(current_word)
                set_bytes += word_bytes
            else:
                log.debug("Packet data size reached. Returning")
                self.untested.insert(0, current_word)
                return new_data
        return new_data

    def bisect(self):
        """Bisect a list of words and return both halves"""
        log.debug("Bisecting data")
        # If no bisected lists exists repopulate them
        if self.bisected == []:
            term_list = self.to_bisect.pop(0)
            half = len(term_list)/2
            self.bisected += [term_list[:half], term_list[half:]]
        return self.bisected.pop(0)

    def add_bisected(self, blocked_terms):
        if isinstance(blocked_terms, ListType):
            log.debug("Adding new blocked terms")
            self.to_bisect.append(blocked_terms)
        else:
            raise TypeError("{0} ".format(self.__class__.__name__) +
                            "can only be added with a list of terms to bisect")

class ExampleTCPT(tcpt.TCPTest):
    name = "Term RST Filtering - Bisect"
    description = ("Tests for TCP RST based term filtering "
                   "by bisecting a list of key terms.")
    author = "Seamus Tuohy"
    version = "0.1"
    # TODO Need to implement proper PMTU detection instead of
    #      using the below to create an assumed network boundry
    tcp_ip_overhead = 40
    mtu = 1280

    inputFile = ['file', 'f', None,
                 'List of keywords to use for censorship testing']
    input_obj = None
    requiresRoot = False
    requiresTor = False
    requiredOptions = ['file']
    #requiredTestHelpers = {'backend': 'tcp-directionality'}

    def _setUp(self):
        log.debug("INPUTS OBJ={0}".format(id(self.input_obj)))

        log.debug("INPUTS ID={0}".format(id(self.inputs)))
        self.inputGenerator = self.inputs
        log.debug("MY INPUT ID={0}".format(id(self.inputGenerator)))
        super(ExampleTCPT, self)._setUp()

    def inputProcessor(self, filename):
        #print inspect.stack()[0][3]

        # Set max packet size boundry
        #packet_load_bounds = self.mtu - self.tcp_ip_overhead
        # TODO Swap out next line with previous
        packet_load_bounds = 200

        test_set = []
        set_bytes = 0

        with PacketDataBisector(filename, max_byte_length=packet_load_bounds) as bisector:
            for packet in bisector:
                log.debug("PACKET: {0}".format(packet))
                packet_blocked = yield packet
                if packet_blocked is True:
                    log.debug("[-] Packet Blocked: {0}".format(packet))
                    bisector.add_bisected(packet)
                else:
                    log.debug("RETURN: {0}".format(packet_blocked))
                    log.debug("[+] Packet NOT Blocked: {0}".format(packet))

    def test_bisect_send(self):
        def is_in_keywords(keywords):
            print(str(dir(self)))
            if "BLOCKMEBLOCKMEBLOCKME" in keywords:
                log.debug("[-] FOUND blocked term KEYWORDS: {0}".format(keywords))
                #yield True
                # with open('/ooni/private/keyword_oti.txt', "a+") as term_file:
                #     for term in keywords:
                #         term_file.write(term + u"\n")
                self.inputGenerator.send(True)
                return True
            else:
                #send(False)
                log.debug("[+] NOT blocked term KEYWORDS: {0}".format(keywords))
                #yield False
                self.inputGenerator.send(False)
                return False

        log.debug("KEYWORDS: {0}".format(self.input))
        d = defer.maybeDeferred(is_in_keywords, self.input)
        return d
