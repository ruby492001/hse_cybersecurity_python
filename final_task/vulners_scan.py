import json
import requests
import sys


class VulnersScanner:
    def __init__(self, api_key: str):
        self.__api_key = api_key
        self.__libs_json = None
        self.__scan_result = {}
        self.__base_url = "https://vulners.com/api/v3/burp/softwareapi/"

    def load_lib_list_from_file(self, path_to_file: str) -> None:
        with open(path_to_file, 'r') as f:
            self.__libs_json = json.load(f)

    def exec_scan(self) -> None:
        for lib in self.__libs_json:
            self.__scan_result[lib['Program']] = self.__exec_one_scan(lib['Program'], lib['Version'])

    def print_report(self) -> None:
        for name in self.__scan_result:
            value = self.__scan_result[name]
            print(f'Name: {name}')
            __scan_result = f'\tScan Result: {value['result']}'
            if value['result'] != 'OK':
                __scan_result += f'({value['errorText']})'
            print(__scan_result)
            if value['result'] != 'OK':
                continue
            print(f'\tExploit exists: {value['contain_exploit']}')
            print(f'\tCVE-list:\n\t\t{'\n\t\t'.join(value['cves'])}')

    def __exec_one_scan(self, program: str, version: str) -> {}:
        request_data = {
            "software": program,
            "version": version,
            "apiKey": self.__api_key,
            "type": "software"
        }
        request_headers = {
            "Content-Type": "application/json"
        }
        result = {}
        response = requests.post(self.__base_url, headers=request_headers, json=request_data)
        if response.status_code != 200:
            raise RuntimeError(f'Error occur: {response.status_code}')

        response_json = response.json()
        result['result'] = response_json['result']

        if response_json['result'] != 'OK':
            result['errorText'] = response_json['data']
            return result

        result['contain_exploit'] = False
        result['cves'] = []

        for value in response_json['data']["search"]:
            if str(value["_source"]["type"]).find('exploit') != -1:
                result['contain_exploit'] = True
            for cve in value["_source"]["cvelist"]:
                result['cves'].append(str(cve))

        return result


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: API-token json_file_name")
        sys.exit(-1)

    token = sys.argv[1]
    path = sys.argv[2]

    scaner = VulnersScanner(token)
    scaner.load_lib_list_from_file(path)
    scaner.exec_scan()
    scaner.print_report()