from bitcoinpython import PrivateKeyBTC, PrivateKeyTestnetBTC
from cashaddress import convert
from bitcoinpython import get_balance, get_transactions_btc, get_balance_btc
from bitcoinpython.network import NetworkAPI


# k = Key('L3KavUvcjBj7pzKBMS4doKyJpBY4nJJbm31VnVwhcC26mTvCP3Lh')
# k = PrivateKeyTestnet('cPW1zL9JJzgTKwQyHYeQ8KE5Cdo33fGE15QcZiWDCWKHhU43KsU2')


k = PrivateKeyTestnetBTC('92dhbLZZPnZ9pNzJdRAHtXonoN5n9fA93ZiWCmYxGdekfAj6d8N')
# print(k.public_key)
print(k.address)
print(k.to_wif())
# print(k.public_point)
# address = convert.to_legacy_address(k.address)
# print(address)
# bchaddr = convert.to_cash_address('13A8QNwEeuYyvcPSJwR4F5xDr6RUryLVfw')
# print(bchaddr)
# print(k.to_wif())
print(k.get_balance(currency='btc'))
# print(k.unspents)
# print(k.transactions)
print(k.get_transactions())
print(k.get_unspents())
txid = k.send([('2MxXdQcCjToMKbq3XiLcdPXENnbFMLe8xcT', 0.00001, 'btc')])
print(txid)

# print(get_balance('qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878', currency='bch'))
# print(get_balance_btc('bc1q5j8j9y55mc05ws84smk36ndau4ptj9yj72eldz', currency='BTC'))

# print(get_balance('qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878', currency='bch'))
# print(get_balance_btc('19xMengSsni75W4sBZFhswf4uzt4auKLzd', currency='BTC'))
# print(get_transactions_btc('19xMengSsni75W4sBZFhswf4uzt4auKLzd')[0])
# print(NetworkAPI.get_balance_testnet('34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo'))
