#!/usr/bin/env python

import argparse
import re
import sys
import inspect
import types

from mtools.util.logevent import LogEvent
from mtools.util.cmdlinetool import LogFileTool

class MLogScrubTool(LogFileTool):
    
    VALUE_MATCH_PATTERN = "(\"[^(?:\\\")\\}]*?\"|.*?)(,|\\s\\})"

    DEFAULT_KEY_PATTERN = "\S*?name\S*?|\S*?date\S*?"

    DEFAULT_REPLACE_STRING = "xxx"
    
    def __init__(self):
        LogFileTool.__init__(self, multiple_logfiles=True, stdin_allowed=True)

        self.argparser.description = 'mongod/mongos log file scrubber. Use parameters to specify sensitive mongo fields which should be scrubbed.'
        self.argparser.add_argument('--keylist', nargs='?', type=argparse.FileType('r'), help='path to file containing newline-separated key names or regexps for detecting keys whose values may be sensitive and should be scrubbed.')
        self.argparser.add_argument('--replacement', nargs='?', action='store', default=self.DEFAULT_REPLACE_STRING, help='string with which to replace values of sensitive fields (default '+self.DEFAULT_REPLACE_STRING+').')

    def _field_matcher(self):
        """ builds and returns a regexp for matching sensitive fields """
        # groups: 1=key, 2=value, 3=ending
        return re.compile(self._build_field_regexp())

    def _output_line(self, logevent, matcher):
        """ prints the final line (with regexps applied) """
        line = logevent.line_str
        print matcher.sub("\\1: " + self.args['replacement'] + "\\3", line)
    
    def _build_field_regexp(self):
        """ builds regular expression for matching and replacing sensitive values, using the keylist file if provided """
        if self.args['keylist'] != None:
            keylist = []
            # keylist_file = open(self.args['keylist'], 'r')
            for k in self.args['keylist']:
                keylist.append("\\s" + k.rstrip())
            return "(" + "|".join(keylist) + "):\\s" + self.VALUE_MATCH_PATTERN
        else:
            # if no keylist specified, return a default best-guess
            return "(" + self.DEFAULT_KEY_PATTERN + "):\\s" + self.VALUE_MATCH_PATTERN
            
    def _logfile_generator(self):
        """ generator method that yields each line of the logfile(s). """
        for logfile in self.args['logfile']:
            for logevent in logfile:
                yield logevent

    def run(self, arguments=None):
        """ parses the logfile, printing each line with sensitive values having been obfuscated. """

        # now parse arguments and post-process
        LogFileTool.run(self, arguments)
        #self.args = dict((k, self.args[k] if k in ['logfile', 'patternfile'] else self._arrayToString(self.args[k])) for k in self.args)

        # require 1 log file (either through stdin or as parameter)
        if len(self.args['logfile']) == 0:
            raise SystemExit('Error: Need 1 log file, either as command line parameter or through stdin.')

        if not 'logfile' in self.args or not self.args['logfile']:
            raise SystemExit('no logfile found.')

        matcher = self._field_matcher()
        for logevent in self._logfile_generator():
            self._output_line(logevent, matcher)

if __name__ == '__main__':

    tool = MLogScrubTool()
    tool.run()

