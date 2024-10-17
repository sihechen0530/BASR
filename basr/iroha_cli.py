from threading import Thread
import time, random

from iroha import Iroha, IrohaCrypto, IrohaGrpc
import packet as pkt, hashlib

class iroha_cli:
    def __init__(self, ip):
        self.net = IrohaGrpc('127.0.0.1:50051')
        self.iroha = Iroha(self.ip2acc(ip))
        with open('/home/iroha_config/'+self.ip2acc(ip) + '.priv') as f:
            self.privkey = f.read()
        with open('/home/iroha_config/'+self.ip2acc(ip) + '.pub') as f:
            self.pubkey = f.read()
        self.no = ip[-1:]
        self.key_list = dict()
        self.transfer_q = dict()
        self.iroha_commit_thread = Thread(target=self.iroha_commit)
        self.iroha_commit_thread.start()
    
    def iroha_commit(self):
        # time.sleep(int(self.no)*10)
        while True:
            try:
                for ip in self.transfer_q:
                    print("Start committing...")
                    value = self.transfer_q[ip]
                    if value > 0:
                        tx_list = [
                            self.iroha.command(
                            'TransferAsset',
                            src_account_id = 'bank@test',
                            dest_account_id = self.ip2acc(ip),
                            asset_id='tv#test',
                            amount=str(value)
                            )
                        ]
                        my_tx = self.iroha.transaction(tx_list)
                        IrohaCrypto.sign_transaction(my_tx, self.privkey)
                        self.net.send_tx(my_tx)
                    elif value < 0:
                        tx_list = [
                            self.iroha.command(
                            'TransferAsset',
                            src_account_id = self.ip2acc(ip),
                            dest_account_id = 'bank@test',
                            asset_id='tv#test',
                            amount=str(abs(value))
                            )
                        ]
                        my_tx = self.iroha.transaction(tx_list)
                        IrohaCrypto.sign_transaction(my_tx, self.privkey)
                        self.net.send_tx(my_tx)
                    self.transfer_q[ip] = 0
                    time.sleep(5)
            except:
                time.sleep(5)
                pass


    def ip2acc(self, ip):
        account = hashlib.md5(ip.encode()).hexdigest()
        return account+'@test'

    def signpacket(self, packet):
        pkt.sign(packet, self.privkey)

    def verify(self, sender_ip, packet):
        query = self.iroha.query('GetSignatories', account_id=self.ip2acc(sender_ip))
        IrohaCrypto.sign_query(query, self.privkey)
        response = self.net.send_query(query)
        sender_key = response.signatories_response.keys[0]
        self.key_list[sender_ip] = sender_key

        pkt.verify(packet, self.key_list[sender_ip])

    def do_transaction(self, packet):
        self.subtract_tv(packet.OrigIP)
        if packet.Hop1 != '0.0.0.0':
            self.add_tv(packet.Hop1)
            if packet.Hop2 != '0.0.0.0':
                self.add_tv(packet.Hop2)
                if packet.Hop3 != '0.0.0.0':
                    self.add_tv(packet.Hop3)
                    if packet.Hop4 != '0.0.0.0':
                        self.add_tv(packet.Hop4)
                        if packet.Hop5 != '0.0.0.0':
                            self.add_tv(packet.Hop5)
                            if packet.Hop6 != '0.0.0.0':
                                self.add_tv(packet.Hop6)
                                if packet.Hop7 != '0.0.0.0':
                                    self.add_tv( packet.Hop7)
                                    if packet.Hop8 != '0.0.0.0':
                                        self.add_tv(packet.Hop8)

    def add_tv(self, ip):
        if ip not in self.transfer_q:
            self.transfer_q[ip] = 1
        else:
            self.transfer_q[ip] += 1
        print("adding trust value to {}".format(ip))

    def subtract_tv(self, ip):
        if ip not in self.transfer_q:
            self.transfer_q[ip] = -1
        else:
            self.transfer_q[ip] -= 1
        print("subtracting trust value from {}".format(ip))

    def get_tv(self, ip):
        tv = 0
        query = self.iroha.query('GetAccountAssets', account_id=self.ip2acc(ip))
        IrohaCrypto.sign_query(query, self.privkey)
        response = self.net.send_query(query)
        assets = response.account_assets_response.account_assets
        for asset in assets:
            tv = int(asset.balance)
        print("{} has trust value {}".format(ip, tv))
        return tv

    def initialize(self):
        acc = 'bank@test'
        iroha = Iroha(acc)
        net = IrohaGrpc('127.0.0.1:50051')
        privkey = ""
        with open('/home/iroha_config/'+acc+'.priv') as f:
            privkey = f.read()
        bank_tx = iroha.transaction(
            [iroha.command(
                'AddAssetQuantity',
                asset_id = 'tv#test',
                amount = '20'
            )]
        )
        IrohaCrypto.sign_transaction(bank_tx, privkey)
        net.send_tx(bank_tx)

        my_tx = self.iroha.transaction(
            [self.iroha.command(
                'AddAssetQuantity',
                asset_id = 'tv#test',
                amount = '20'
            )]
        )
        IrohaCrypto.sign_transaction(my_tx, self.privkey)
        self.net.send_tx(my_tx)

            

'''
import ed25519

sk = bytes.fromhex('69c2ee77e79773200f290479433789fa6da65abc9ed2bfd9e5d06f8da21851dc')
pk = ed25519.publickey_unsafe(sk)
signature = ed25519.signature_unsafe(b'hello', sk, pk)
print(pk.hex())
'''