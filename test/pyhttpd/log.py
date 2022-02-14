import os
import re
import time
from datetime import datetime, timedelta
from io import SEEK_END
from typing import List, Tuple, Any


class HttpdErrorLog:
    """Checking the httpd error log for errors and warnings, including
       limiting checks from a last known position forward.
    """

    RE_ERRLOG_ERROR = re.compile(r'.*\[(?P<module>[^:]+):error].*')
    RE_ERRLOG_WARN = re.compile(r'.*\[(?P<module>[^:]+):warn].*')
    RE_APLOGNO = re.compile(r'.*\[(?P<module>[^:]+):(error|warn)].* (?P<aplogno>AH\d+): .+')
    RE_SSL_LIB_ERR = re.compile(r'.*\[ssl:error].* SSL Library Error: error:(?P<errno>\S+):.+')

    def __init__(self, path: str):
        self._path = path
        self._ignored_modules = []
        self._ignored_lognos = set()
        self._ignored_patterns = []
        # remember the file position we started with
        self._start_pos = 0
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                self._start_pos = fd.seek(0, SEEK_END)
        self._last_pos = self._start_pos
        self._last_errors = []
        self._last_warnings = []
        self._observed_erros = set()
        self._observed_warnings = set()

    def __repr__(self):
        return f"HttpdErrorLog[{self._path}, errors: {' '.join(self._last_errors)}, " \
               f"warnings: {' '.join(self._last_warnings)}]"

    @property
    def path(self) -> str:
        return self._path

    def clear_log(self):
        if os.path.isfile(self.path):
            os.remove(self.path)
        self._start_pos = 0
        self._last_pos = self._start_pos
        self._last_errors = []
        self._last_warnings = []
        self._observed_erros = set()
        self._observed_warnings = set()

    def set_ignored_modules(self, modules: List[str]):
        self._ignored_modules = modules.copy() if modules else []

    def set_ignored_lognos(self, lognos: List[str]):
        if lognos:
            for l in lognos:
                self._ignored_lognos.add(l)

    def add_ignored_patterns(self, patterns: List[Any]):
        self._ignored_patterns.extend(patterns)

    def _is_ignored(self, line: str) -> bool:
        for p in self._ignored_patterns:
            if p.match(line):
                return True
        m = self.RE_APLOGNO.match(line)
        if m and m.group('aplogno') in self._ignored_lognos:
            return True
        return False

    def get_recent(self, advance=True) -> Tuple[List[str], List[str]]:
        """Collect error and warning from the log since the last remembered position
        :param advance: advance the position to the end of the log afterwards
        :return: list of error and list of warnings as tuple
        """
        self._last_errors = []
        self._last_warnings = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._last_pos, os.SEEK_SET)
                for line in fd:
                    if self._is_ignored(line):
                        continue
                    m = self.RE_ERRLOG_ERROR.match(line)
                    if m and m.group('module') not in self._ignored_modules:
                        self._last_errors.append(line)
                        continue
                    m = self.RE_ERRLOG_WARN.match(line)
                    if m:
                        if m and m.group('module') not in self._ignored_modules:
                            self._last_warnings.append(line)
                            continue
                if advance:
                    self._last_pos = fd.tell()
            self._observed_erros.update(set(self._last_errors))
            self._observed_warnings.update(set(self._last_warnings))
        return self._last_errors, self._last_warnings

    def get_recent_count(self, advance=True):
        errors, warnings = self.get_recent(advance=advance)
        return len(errors), len(warnings)

    def ignore_recent(self):
        """After a test case triggered errors/warnings on purpose, add
           those to our 'observed' list so the do not get reported as 'missed'.
           """
        self._last_errors = []
        self._last_warnings = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._last_pos, os.SEEK_SET)
                for line in fd:
                    if self._is_ignored(line):
                        continue
                    m = self.RE_ERRLOG_ERROR.match(line)
                    if m and m.group('module') not in self._ignored_modules:
                        self._observed_erros.add(line)
                        continue
                    m = self.RE_ERRLOG_WARN.match(line)
                    if m:
                        if m and m.group('module') not in self._ignored_modules:
                            self._observed_warnings.add(line)
                            continue
                self._last_pos = fd.tell()

    def get_missed(self) -> Tuple[List[str], List[str]]:
        errors = []
        warnings = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._start_pos, os.SEEK_SET)
                for line in fd:
                    if self._is_ignored(line):
                        continue
                    m = self.RE_ERRLOG_ERROR.match(line)
                    if m and m.group('module') not in self._ignored_modules \
                            and line not in self._observed_erros:
                        errors.append(line)
                        continue
                    m = self.RE_ERRLOG_WARN.match(line)
                    if m:
                        if m and m.group('module') not in self._ignored_modules \
                                and line not in self._observed_warnings:
                            warnings.append(line)
                            continue
        return errors, warnings

    def scan_recent(self, pattern: re, timeout=10):
        if not os.path.isfile(self.path):
            return False
        with open(self.path) as fd:
            end = datetime.now() + timedelta(seconds=timeout)
            while True:
                fd.seek(self._last_pos, os.SEEK_SET)
                for line in fd:
                    if pattern.match(line):
                        return True
                if datetime.now() > end:
                    raise TimeoutError(f"pattern not found in error log after {timeout} seconds")
                time.sleep(.1)
        return False
