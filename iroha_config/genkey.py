import hashlib, socket, os

def ip2acc(ip):
    account = hashlib.md5(ip.encode()).hexdigest()
    return account+'@test'

NODE_COUNT = 10
ip_list = ['10.0.56.{}'.format(i) for i in range(1,NODE_COUNT+1)]
for ip in ip_list:
    acc = ip2acc(ip)
    print(acc)
    os.system('./iroha-cli --new_account --account_name {}'.format(acc))
