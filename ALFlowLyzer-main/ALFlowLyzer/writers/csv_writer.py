#!/usr/bin/env python3

import csv
from .strategy import Strategy

class CSVWriter(Strategy):
    def __derive_headers(self, data: list) -> list:
        headers = []
        seen = set()
        for data_row in data:
            for key in data_row.keys():
                if key in seen:
                    continue
                headers.append(key)
                seen.add(key)
        return headers

    def write(self, file_address: str, data: list, writing_mode: str = 'w',
            only_headers: bool = False, headers: list = None) -> None:
        with open(file_address, writing_mode, newline='') as f:
            writer = csv.writer(f)
            if headers is None:
                headers = self.__derive_headers(data)

            if len(headers) == 0:
                return
            if only_headers:
                writer.writerow(headers)
                return

            if len(data) == 0:
                return

            for data_row in data:
                row = []
                for header in headers:
                    row.append(data_row.get(header, ""))
                writer.writerow(row)
            print(f">> {len(data)} number of flows has been written in {file_address} file.")