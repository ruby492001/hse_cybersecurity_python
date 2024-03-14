import sys

import requests as req
import time


class VirusTotal:
    def __init__(self, api_key):
        self.__api_key = api_key
        self.__base_url = 'https://www.virustotal.com/api/v3'
        self.__file_hash = ''
        self.__analyses_id = ''
        self.__scan_result = None
        self.__analyse_result = None

    def load_file(self, file_path: str, zip_pwd: str = "") -> None:
        headers = {
            "accept": "application/json",
            "x-apikey": self.__api_key
        }

        payload = {}
        if zip_pwd:
            payload['password'] = zip_pwd

        with open(file_path, "rb") as file:
            file_to_load = {"file": (file_path, file)}
            load_file_response = req.post(f'{self.__base_url}/files', files=file_to_load, headers=headers,
                                          data=payload)
        if load_file_response.status_code != 200:
            raise RuntimeError(f'Error occur while load file:\n{load_file_response.text}')

        self.__analyses_id = str(load_file_response.json()['data']['id'])          #id анализа

        # по id загруженного файла получаем хэш файла
        response = req.get(f'{self.__base_url}/analyses/{self.__analyses_id}', headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f'Error occur while get file hash:\n{response.text}')
        self.__file_hash = response.json()['meta']['file_info']['md5']

    def scan_file(self) -> None:
        if self.__analyses_id.count == 0:
            raise RuntimeError('You need first load file')

        headers = {
            "accept": "application/json",
            "x-apikey": self.__api_key
        }
        while True:
            response = req.get(f'{self.__base_url}/analyses/{self.__analyses_id}', headers=headers)

            if response.status_code != 200:
                raise RuntimeError(f'Error occur while scan file:\n{response.text}')

            response_json = response.json()
            status = response_json['data']['attributes']['status']

            if status == 'completed':
                break

            # если файл находится в обработке -> спим и заново стучимся к API, пока не получим статус completed
            if status == 'queued':
                time.sleep(10)
                continue

            raise RuntimeError(f"Undefined file status: {status}")

        self.__scan_result = response_json['data']['attributes']['results']

    def analyse_behavior(self) -> None:
        if self.__file_hash.count == 0:
            raise RuntimeError(f"You need first load file")

        headers = {
            "accept": "application/json",
            "x-apikey": self.__api_key
        }

        response = req.get(f'{self.__base_url}/files/{self.__file_hash}/behaviour_summary', headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f'Error occur while analyse behavior file:\n{response.text}')

        self.__analyse_result = response.json()['data']

    def print_av_statistics(self) -> None:
        detected_list = []
        for av_name, result in self.__scan_result.items():
            if result['result'] is not None:
                detected_list.append(av_name)
        if len(detected_list) > 0:
            print(f'Detected AV list: {', '.join(detected_list)}')
        else:
            print(f'No virus detected')

    def print_av_detected(self, search_name: str) -> None:
        for av_name, result in self.__scan_result.items():
            if av_name == search_name:
                print(f'{av_name} {'undetect' if result['result'] is None else 'DETECT'} virus')

    def print_dns_lookup(self) -> None:
        if 'dns_lookups' not in self.__analyse_result:
            print('DNS lookups does not exists')
            return
        print('DNS lookup info:')
        for dns_info in self.__analyse_result['dns_lookups']:
            print(f'\tHostname: {dns_info['hostname']} IP list: {dns_info['resolved_ips'] if 'resolved_ips' in dns_info else 'No resolved'}')

    def analyse_file_and_print(self, file_path: str, zip_pwd: str = "") -> None:
        """Сканируем файл и проводим его поведенческий анализ"""
        vt.load_file(file_path, zip_pwd)
        vt.scan_file()
        vt.analyse_behavior()

        """Выводим информацию по всем антивирусам и информацию по заданному набору антивирусов"""
        self.print_av_statistics()
        for av_name in ['Fortinet', 'McAfee', 'Yandex', 'Sophos']:
            self.print_av_detected(av_name)

        """Выводим информацию по поведенческому анализу"""
        self.print_dns_lookup()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: API-token file [optional archive pwd if file is encrypted archive]")
        sys.exit(-1)

    token = sys.argv[1]
    path = sys.argv[2]
    pwd = ''
    if len(sys.argv) >= 4:
        pwd = sys.argv[3]


vt = VirusTotal(token)
vt.analyse_file_and_print(path, pwd)

