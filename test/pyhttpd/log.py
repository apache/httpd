import os
import re
import time
from datetime import datetime, timedelta
from io import SEEK_END
from typing import List, Tuple, Any


class HttpdErrorLog:
    """Checking the httpd error log for errors and warnings, including
       limiting checks from a recent known position forward.
    """

    RE_ERRLOG_WARN = re.compile(r'.*\[[^:]+:warn].*')
    RE_ERRLOG_ERROR = re.compile(r'.*\[[^:]+:error].*')
    RE_APLOGNO = re.compile(r'.*\[[^:]+:(error|warn)].* (?P<aplogno>AH\d+): .+')

    def __init__(self, path: str):
        self._path = path
        self._ignored_matches = []
        self._ignored_lognos = set()
        # remember the file position we started with
        self._start_pos = 0
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                self._start_pos = fd.seek(0, SEEK_END)
        self._recent_pos = self._start_pos
        self._recent_errors = []
        self._recent_warnings = []
        self._caught_errors = set()
        self._caught_warnings = set()
        self._caught_matches = set()

    def __repr__(self):
        return f"HttpdErrorLog[{self._path}, errors: {' '.join(self._recent_errors)}, " \
               f"warnings: {' '.join(self._recent_warnings)}]"

    @property
    def path(self) -> str:
        return self._path

    def clear_log(self):
        if os.path.isfile(self.path):
            os.truncate(self.path, 0)
        self._start_pos = self._recent_pos = 0
        self._recent_errors = []
        self._recent_warnings = []
        self._caught_errors = set()
        self._caught_warnings = set()
        self._caught_matches = set()

    def _lookup_matches(self, line: str, matches: List[str]) -> bool:
        for m in matches:
            if re.match(m, line):
                return True
        return False

    def _lookup_lognos(self, line: str, lognos: set) -> bool:
        if len(lognos) > 0:
            m = self.RE_APLOGNO.match(line)
            if m and m.group('aplogno') in lognos:
                return True
        return False

    def clear_ignored_matches(self):
        self._ignored_matches = []

    def add_ignored_matches(self, matches: List[str]):
        for m in matches:
            self._ignored_matches.append(re.compile(m))

    def clear_ignored_lognos(self):
        self._ignored_lognos = set()

    def add_ignored_lognos(self, lognos: List[str]):
        for l in lognos:
            self._ignored_lognos.add(l)

    def _is_ignored(self, line: str) -> bool:
        if self._lookup_matches(line, self._ignored_matches):
            return True
        if self._lookup_lognos(line, self._ignored_lognos):
            return True
        return False

    def ignore_recent(self, lognos: List[str] = [], matches: List[str] = []):
        """After a test case triggered errors/warnings on purpose, add
           those to our 'caught' list so the do not get reported as 'missed'.
           """
        self._recent_errors = []
        self._recent_warnings = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._recent_pos, os.SEEK_SET)
                lognos_set = set(lognos)
                for line in fd:
                    if self._is_ignored(line):
                        continue
                    if self._lookup_matches(line, matches):
                        self._caught_matches.add(line)
                        continue
                    m = self.RE_ERRLOG_WARN.match(line)
                    if m and self._lookup_lognos(line, lognos_set):
                        self._caught_warnings.add(line)
                        continue
                    m = self.RE_ERRLOG_ERROR.match(line)
                    if m and self._lookup_lognos(line, lognos_set):
                        self._caught_errors.add(line)
                        continue
                self._recent_pos = fd.tell()

    def get_missed(self) -> Tuple[List[str], List[str]]:
        errors = []
        warnings = []
        self._recent_errors = []
        self._recent_warnings = []
        if os.path.isfile(self._path):
            with open(self._path) as fd:
                fd.seek(self._start_pos, os.SEEK_SET)
                for line in fd:
                    if self._is_ignored(line):
                        continue
                    if line in self._caught_matches:
                        continue
                    m = self.RE_ERRLOG_WARN.match(line)
                    if m and line not in self._caught_warnings:
                        warnings.append(line)
                        continue
                    m = self.RE_ERRLOG_ERROR.match(line)
                    if m and line not in self._caught_errors:
                        errors.append(line)
                        continue
                self._start_pos = self._recent_pos = fd.tell()
        self._caught_errors = set()
        self._caught_warnings = set()
        self._caught_matches = set()
        return errors, warnings

    def scan_recent(self, pattern: re.Pattern, timeout=10):
        if not os.path.isfile(self.path):
            return False
        with open(self.path) as fd:
            end = datetime.now() + timedelta(seconds=timeout)
            while True:
                fd.seek(self._recent_pos, os.SEEK_SET)
                for line in fd:
                    if pattern.match(line):
                        return True
                if datetime.now() > end:
                    raise TimeoutError(f"pattern not found in error log after {timeout} seconds")
                time.sleep(.1)
        return False
