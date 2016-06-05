from ooni import nettest
from twisted.internet import defer

import re

class UrlGeneratorWithSend(object):
    def __init__(self):
        """Create initial list and set generator state."""
        self.urls = ["http://www.torproject.org",
                     "https://ooni.torproject.org"]
        self.current = 0

    def __iter__(self):
        return self

    def __next__(self):
        try:
            cur = self.urls[self.current]
            self.current += 1
            return cur
        except IndexError:
            raise StopIteration

    # Python 2 & 3 generator compatibility
    next = __next__

    def send(self, returned):
        """Appends a value to self.urls when activated"""
        if returned is not None:
            print("Value {0} sent to generator".format(returned))
            self.urls.append(returned)


class TestUrlList(nettest.NetTestCase):

    # Adding custom generator here
    inputs = UrlGeneratorWithSend()

    def postProcessor(self, measurements):
        """If any HTTPS url's are passed send back an HTTP url."""
        if re.match("^https", self.input):
            http_version = re.sub("https", "http", self.input, 1)
            self.inputs.send(http_version)
        return self.report

    def test_url(self):
        self.report['tested'] = [self.input]
        return defer.succeed(1)
