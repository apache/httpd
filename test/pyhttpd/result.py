import json
from datetime import timedelta
from typing import Optional, Dict, List


class ExecResult:

    def __init__(self, args: List[str], exit_code: int,
                 stdout: bytes, stderr: bytes = None,
                 stdout_as_list: List[bytes] = None,
                 duration: timedelta = None):
        self._args = args
        self._exit_code = exit_code
        self._stdout = stdout if stdout is not None else b''
        self._stderr = stderr if stderr is not None else b''
        self._duration = duration if duration is not None else timedelta()
        self._response = None
        self._results = {}
        self._assets = []
        # noinspection PyBroadException
        try:
            if stdout_as_list is None:
                out = self._stdout.decode()
            else:
                out = "[" + ','.join(stdout_as_list) + "]"
            self._json_out = json.loads(out)
        except:
            self._json_out = None

    def __repr__(self):
        out = [
            f"ExecResult[code={self.exit_code}, args={self._args}\n",
            "----stdout---------------------------------------\n",
            self._stdout.decode(),
            "----stderr---------------------------------------\n",
            self._stderr.decode()
        ]
        return ''.join(out)

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def args(self) -> List[str]:
        return self._args

    @property
    def outraw(self) -> bytes:
        return self._stdout

    @property
    def stdout(self) -> str:
        return self._stdout.decode()

    @property
    def json(self) -> Optional[Dict]:
        """Output as JSON dictionary or None if not parseable."""
        return self._json_out

    @property
    def stderr(self) -> str:
        return self._stderr.decode()

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def response(self) -> Optional[Dict]:
        return self._response

    @property
    def results(self) -> Dict:
        return self._results

    @property
    def assets(self) -> List:
        return self._assets

    def add_response(self, resp: Dict):
        if self._response:
            resp['previous'] = self._response
        self._response = resp

    def add_results(self, results: Dict):
        self._results.update(results)
        if 'response' in results:
            self.add_response(results['response'])

    def add_assets(self, assets: List):
        self._assets.extend(assets)
