from iroha import Iroha, IrohaCrypto, IrohaGrpc

acc = 'bank@test'
iroha = Iroha(acc)
net = IrohaGrpc('127.0.0.1:50051')

privkey = ""
pubkey = ""
with open('/home/iroha_config/'+acc+'.priv') as f:
    privkey = f.read()
with open('/home/iroha_config/'+acc+'.pub') as f:
    pubkey = f.read()

my_tx = iroha.transaction(
    [iroha.command(
        'AddAssetQuantity',
        asset_id = 'tv#test',
        amount = '20'
    )]
)
IrohaCrypto.sign_transaction(my_tx, privkey)
net.send_tx(my_tx)
for status in net.tx_status_stream(my_tx):
    print(status)