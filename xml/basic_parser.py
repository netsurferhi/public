from xml.sax import saxutils, handler, make_parser
import sys, string


# --- The ContentHandler
class ContentGenerator(handler.ContentHandler):
    def __init__(self, out = sys.stdout):
        handler.ContentHandler.__init__(self)
        self._out = out
        self.indent = 0
        self.spaces = ''
    # ContentHandler methods
    
    def startDocument(self):
        self._out.write('\n<?xml version="1.0" encoding="iso-8859-1"?>\n')
        self.indent += 2
        self.spaces = " " * self.indent
    
    def endDocument(self):
        self._out.write('</?xml version="1.0" encoding="iso-8859-1"?>\n')
    
    def startElement(self, name, attrs):
        if name.find('\n') >= 0:
            name = name[0:name.find('\n')]
        self._out.write(self.spaces+'<' + name)
        for (name, value) in attrs.items():
            self._out.write(' %s="%s"' % (name, saxutils.escape(value)))
        self._out.write('>\n')
        self.indent += 2
        self.spaces = " " * self.indent
    
    def endElement(self, name):
        if name.find('\n') >= 0:
            name = name[0:name.find('\n')]
        self.indent -= 2
        self.spaces = " " * self.indent
        self._out.write(self.spaces+'</%s>\n' % (name))
    
    def characters(self, content):
        if content.find('\n') >= 0:
            content = content[0:content.find('\n')]
        if len(content) > 0:
            self._out.write(self.spaces+saxutils.escape(content)+'\n')
    
    def ignorableWhitespace(self, content):
        self._out.write('*'+content+'*')
        self._out.write(self.spaces)
    
    def processingInstruction(self, target, data):
        self._out.write(self.spaces+'<?%s %s?>\n' % (target, data))

# --- The main program

parser = make_parser()
parser.setContentHandler(ContentGenerator())
parser.parse('juniper-interfaces.xml')
