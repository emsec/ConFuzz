import multiprocessing
import subprocess
import sys

import serial.tools.list_ports

from main_fuzzer import MainFuzzer


class ClusterFuzzer:
    """This script can be used to split up the test cases of a fuzzer equally over multiple boards."""

    # The number of boards used in parallel.
    BATCH_SIZE = 16
    # The cluster only consists of Basys3 boards.
    BOARD = "basys3"
    # FDTI USB Vendor ID and Product ID of the Basys3 boards.
    VID_PID = "0403:6010"
    # The default OpenOCD port is 6666.
    # For other OpenOCD instances the port is incremented.
    OPENOCD_PORT = 6666

    def __init__(self, fuzzer_name) -> None:
        bus_ports = self._get_bus_ports()
        if len(bus_ports) < self.BATCH_SIZE:
            raise Exception(
                f"{self.BATCH_SIZE} boards requested but only {len(bus_ports)} boards found"
            )
        bus_ports.sort()

        test_case_count = self._get_test_case_count(fuzzer_name)

        if test_case_count < self.BATCH_SIZE:
            self.BATCH_SIZE = test_case_count

        test_cases_per_board, rest = divmod(test_case_count, self.BATCH_SIZE)
        print(f"test_cases_per_board: {test_cases_per_board}, rest: {rest}")

        with multiprocessing.Pool(self.BATCH_SIZE) as p:
            index_start = 1
            for i in range(self.BATCH_SIZE):
                index_end = index_start + test_cases_per_board - 1
                if i < rest:
                    index_end += 1

                print(
                    f"board: {i}, index_start: {index_start}, index_end: {index_end}, openocd_port: {self.OPENOCD_PORT + i}, openocd_bus_port: {bus_ports[i]}"
                )

                p.apply_async(
                    MainFuzzer,
                    kwds={
                        "fuzzer_name": fuzzer_name,
                        "board": self.BOARD,
                        "index_start": index_start,
                        "index_end": index_end,
                        "quiet": True,
                        "openocd_port": self.OPENOCD_PORT + i,
                        "openocd_bus_port": bus_ports[i],
                    },
                )

                index_start += test_cases_per_board

            p.close()
            p.join()

    def _get_bus_ports(self) -> list[str]:
        """Returns a list of the bus ports of the currently activated boards of the cluster."""

        return [
            # Cut :config.interface and only return bus and ports.
            # http://www.linux-usb.org/FAQ.html#i6
            port.location.split(":")[0]
            for port in serial.tools.list_ports.grep(f"{self.VID_PID}.*:1\\.1")
        ]

    def _get_test_case_count(self, fuzzer_name) -> int:
        """Return the total test case count of the specified fuzzer."""

        process = subprocess.run(
            [
                "python",
                "main_fuzzer.py",
                "--fuzzer-name",
                fuzzer_name,
                "--board",
                self.BOARD,
                "--quiet",  # Required so that only digits are in the response.
                "--count-test-cases",
            ],
            capture_output=True,
            check=True,
            encoding="utf-8",
        )

        print(process.stdout)

        # The number of test cases are the only digits in the response.
        test_case_count = ""
        for char in process.stdout:
            if char.isdigit():
                test_case_count += char

        return int(test_case_count)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        fuzzer_name = sys.argv[1]
    else:
        raise ValueError("please specify a fuzzer name")

    try:
        ClusterFuzzer(fuzzer_name)
    finally:
        # Make sure that all OpenOCD processes are killed, regardless of how the script was terminated.
        subprocess.run(["pkill", "openocd"])
