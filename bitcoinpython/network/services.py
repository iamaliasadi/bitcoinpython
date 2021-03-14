import logging

import requests
from cashaddress import convert as cashaddress
from decimal import Decimal

from bitcoinpython.network import currency_to_satoshi
from bitcoinpython.network.meta import Unspent
from bitcoinpython.network.transaction import Transaction, TxPart
from bitcoinpython.utils import bytes_to_hex
from bitcoinpython.exceptions import ExcessiveAddress
from bitcoinpython.transaction import address_to_scriptpubkey

DEFAULT_TIMEOUT = 30

BCH_TO_SAT_MULTIPLIER = 100000000


def set_service_timeout(seconds):
    global DEFAULT_TIMEOUT
    DEFAULT_TIMEOUT = seconds


class InsightAPI:
    MAIN_ENDPOINT = ''
    MAIN_ADDRESS_API = ''
    MAIN_BALANCE_API = ''
    MAIN_UNSPENT_API = ''
    MAIN_TX_PUSH_API = ''
    MAIN_TX_API = ''
    MAIN_TX_AMOUNT_API = ''
    TX_PUSH_PARAM = ''

    @classmethod
    def get_tx_amount(cls, txid, txindex):
        r = requests.get(cls.MAIN_TX_AMOUNT_API.format(
            txid), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)
        return (Decimal(response['vout'][txindex]['value']) * BCH_TO_SAT_MULTIPLIER).normalize()

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.MAIN_TX_PUSH_API, json={
                          cls.TX_PUSH_PARAM: tx_hex, 'network': 'mainnet', 'coin': 'BCH'}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False


class BitcoinDotComAPI():
    """ rest.bitcoin.com API """
    MAIN_ENDPOINT = 'https://rest.bitcoin.com/v2/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'address/details/{}'
    MAIN_UNSPENT_API = MAIN_ENDPOINT + 'address/utxo/{}'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'rawtransactions/sendRawTransaction/{}'
    MAIN_TX_API = MAIN_ENDPOINT + 'transaction/details/{}'
    MAIN_TX_AMOUNT_API = MAIN_TX_API
    MAIN_RAW_API = MAIN_ENDPOINT + 'transaction/details/{}'
    TX_PUSH_PARAM = 'rawtx'

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API.format(address),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        data = r.json()
        balance = data['balanceSat'] + data['unconfirmedBalanceSat']
        return balance

    @classmethod
    def get_transactions(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API.format(address),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return r.json()['transactions']

    @classmethod
    def get_transaction(cls, txid):
        r = requests.get(cls.MAIN_TX_API.format(txid),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)

        return response

    @classmethod
    def get_tx_amount(cls, txid, txindex):
        r = requests.get(cls.MAIN_TX_AMOUNT_API.format(
            txid), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)
        return (Decimal(response['vout'][txindex]['value']) * BCH_TO_SAT_MULTIPLIER).normalize()

    @classmethod
    def get_unspent(cls, address):
        r = requests.get(cls.MAIN_UNSPENT_API.format(address),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return [
            Unspent(currency_to_satoshi(tx['amount'], 'bch'),
                    tx['confirmations'],
                    r.json()['scriptPubKey'],
                    tx['txid'],
                    tx['vout'])
            for tx in r.json()['utxos']
        ]

    @classmethod
    def get_raw_transaction(cls, txid):
        r = requests.get(cls.MAIN_RAW_API.format(
            txid), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)
        return response

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        r = requests.get(cls.MAIN_TX_PUSH_API.format(tx_hex))
        return True if r.status_code == 200 else False


class BitcoreAPI(InsightAPI):
    """ Insight API v8 """
    MAIN_ENDPOINT = 'https://api.bitcore.io/api/BCH/mainnet/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'address/{}'
    MAIN_BALANCE_API = MAIN_ADDRESS_API + '/balance'
    MAIN_UNSPENT_API = MAIN_ADDRESS_API + '/?unspent=true'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'tx/send'
    """ for BTC  """
    MAIN_ENDPOINT_BTC = 'https://api.bitcore.io/api/BTC/mainnet/'
    MAIN_ADDRESS_API_BTC = MAIN_ENDPOINT_BTC + 'address/{}'
    MAIN_BALANCE_API_BTC = MAIN_ADDRESS_API_BTC + '/balance'
    MAIN_UNSPENT_API_BTC = MAIN_ADDRESS_API_BTC + '/?unspent=true'
    MAIN_TX_API_BTC = MAIN_ENDPOINT_BTC + 'tx/{}'
    MAIN_TX_PUSH_API_BTC = MAIN_ENDPOINT_BTC + 'tx/send'
    MAIN_TX_AMOUNT_API_BTC = MAIN_TX_API_BTC

    @classmethod
    def get_unspent(cls, address):
        address = address.replace('bitcoincash:', '')
        r = requests.get(cls.MAIN_UNSPENT_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return [
            Unspent(currency_to_satoshi(tx['value'], 'satoshi'),
                    tx['confirmations'],
                    tx['script'],
                    tx['mintTxid'],
                    tx['mintIndex'])
            for tx in r.json()
        ]

    @classmethod
    def get_unspent_btc(cls, address):
        endpoint = cls.MAIN_UNSPENT_API_BTC + "&limit=100"

        unspents = []

        r = requests.get(endpoint.format(address), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()

        while len(response) > 0:
            unspents.extend(
                Unspent(
                    currency_to_satoshi(tx['value'], 'satoshi'),
                    tx['confirmations'],
                    tx['script'],
                    tx['mintTxid'],
                    tx['mintIndex'],
                )
                for tx in response
            )
            response = requests.get(
                endpoint.format(address) + "&since={}".format(response[-1]['_id']), timeout=DEFAULT_TIMEOUT
            ).json()

        return unspents

    @classmethod
    def get_transactions(cls, address):
        address = address.replace('bitcoincash:', '')
        r = requests.get(cls.MAIN_ADDRESS_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return [tx['mintTxid'] for tx in r.json()]

    @classmethod
    def get_transactions_btc(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API_BTC.format(
            address), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return [tx['mintTxid'] for tx in r.json()]

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.MAIN_BALANCE_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return r.json()['balance']

    @classmethod
    def get_balance_btc(cls, address):
        r = requests.get(cls.MAIN_BALANCE_API_BTC.format(
            address), timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        return r.json()['balance']

    @classmethod
    def get_transaction(cls, txid):
        r = requests.get(cls.MAIN_TX_API.format(txid),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)
        return response

    @classmethod
    def get_transaction_btc(cls, txid):
        r = requests.get(cls.MAIN_TX_API_BTC.format(txid),
                         timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()  # pragma: no cover
        response = r.json(parse_float=Decimal)
        return response


class BlockchairAPI:
    MAIN_ENDPOINT = 'https://api.blockchair.com/bitcoin/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'dashboards/address/{}'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'push/transaction'
    MAIN_TX_API = MAIN_ENDPOINT + 'raw/transaction/{}'
    TEST_ENDPOINT = 'https://api.blockchair.com/bitcoin/testnet/'
    TEST_ADDRESS_API = TEST_ENDPOINT + 'dashboards/address/{}'
    TEST_TX_PUSH_API = TEST_ENDPOINT + 'push/transaction'
    TEST_TX_API = TEST_ENDPOINT + 'raw/transaction/{}'
    TX_PUSH_PARAM = 'data'

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['data'][address]['address']['balance']

    @classmethod
    def get_balance_testnet(cls, address):
        r = requests.get(cls.TEST_ADDRESS_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['data'][address]['address']['balance']

    @classmethod
    def get_transactions(cls, address):
        endpoint = cls.MAIN_ADDRESS_API

        transactions = []
        offset = 0
        txs_per_page = 1000
        payload = {'offset': str(offset), 'limit': str(txs_per_page)}

        r = requests.get(endpoint.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return []
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        response = response['data'][address]
        total_txs = response['address']['transaction_count']

        while total_txs > 0:
            transactions.extend(tx for tx in response['transactions'])

            total_txs -= txs_per_page
            offset += txs_per_page
            payload['offset'] = str(offset)
            r = requests.get(endpoint.format(address),
                             params=payload, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['data'][address]

        return transactions

    @classmethod
    def get_transactions_testnet(cls, address):
        endpoint = cls.TEST_ADDRESS_API

        transactions = []
        offset = 0
        txs_per_page = 1000
        payload = {'offset': str(offset), 'limit': str(txs_per_page)}

        r = requests.get(endpoint.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return []
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        response = response['data'][address]
        total_txs = response['address']['transaction_count']

        while total_txs > 0:
            transactions.extend(tx for tx in response['transactions'])

            total_txs -= txs_per_page
            offset += txs_per_page
            payload['offset'] = str(offset)
            r = requests.get(endpoint.format(address),
                             params=payload, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['data'][address]

        return transactions

    @classmethod
    def get_transaction_by_id(cls, txid):
        r = requests.get(cls.MAIN_TX_API.format(txid), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()['data']
        if not response:  # pragma: no cover
            return None
        return response[txid]['raw_transaction']

    @classmethod
    def get_transaction_by_id_testnet(cls, txid):
        r = requests.get(cls.TEST_TX_API.format(txid), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()['data']
        if not response:  # pragma: no cover
            return None
        return response[txid]['raw_transaction']

    @classmethod
    def get_unspent(cls, address):
        endpoint = cls.MAIN_ADDRESS_API

        unspents = []
        offset = 0
        unspents_per_page = 1000
        payload = {'offset': str(offset), 'limit': str(unspents_per_page)}

        r = requests.get(endpoint.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()

        block_height = response['context']['state']
        response = response['data'][address]
        script_pubkey = response['address']['script_hex']
        total_unspents = response['address']['unspent_output_count']

        while total_unspents > 0:
            unspents.extend(
                Unspent(
                    utxo['value'],
                    block_height - utxo['block_id'] +
                    1 if utxo['block_id'] != -1 else 0,
                    script_pubkey,
                    utxo['transaction_hash'],
                    utxo['index'],
                )
                for utxo in response['utxo']
            )

            total_unspents -= unspents_per_page
            offset += unspents_per_page
            payload['offset'] = str(offset)
            r = requests.get(endpoint.format(address),
                             params=payload, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['data'][address]

        return unspents

    @classmethod
    def get_unspent_testnet(cls, address):
        endpoint = cls.TEST_ADDRESS_API

        unspents = []
        offset = 0
        unspents_per_page = 1000
        payload = {'offset': str(offset), 'limit': unspents_per_page}

        r = requests.get(endpoint.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        block_height = response['context']['state']
        response = response['data'][address]
        script_pubkey = response['address']['script_hex']
        total_unspents = response['address']['unspent_output_count']

        while total_unspents > 0:
            unspents.extend(
                Unspent(
                    utxo['value'],
                    block_height - utxo['block_id'] +
                    1 if utxo['block_id'] != -1 else 0,
                    script_pubkey,
                    utxo['transaction_hash'],
                    utxo['index'],
                )
                for utxo in response['utxo']
            )

            total_unspents -= unspents_per_page
            offset += unspents_per_page
            payload['offset'] = str(offset)
            r = requests.get(endpoint.format(address),
                             params=payload, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['data'][address]

        return unspents

    @classmethod
    def broadcast_tx(
        cls, tx_hex,
    ):  # pragma: no cover
        r = requests.post(cls.MAIN_TX_PUSH_API, data={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False

    @classmethod
    def broadcast_tx_testnet(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.TEST_TX_PUSH_API, data={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        print(r.json())
        return True if r.status_code == 200 else False


class BlockstreamAPI:
    MAIN_ENDPOINT = 'https://blockstream.info/api/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'address/{}'
    MAIN_UNSPENT_API = MAIN_ADDRESS_API + '/utxo'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'tx'
    MAIN_TX_API = MAIN_ENDPOINT + 'tx/{}/hex'
    TEST_ENDPOINT = 'https://blockstream.info/testnet/api/'
    TEST_ADDRESS_API = TEST_ENDPOINT + 'address/{}'
    TEST_UNSPENT_API = TEST_ADDRESS_API + '/utxo'
    TEST_TX_PUSH_API = TEST_ENDPOINT + 'tx'
    TEST_TX_API = TEST_ENDPOINT + 'tx/{}/hex'
    TX_PUSH_PARAM = 'data'

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        funded = response['chain_stats']['funded_txo_sum'] + \
            response['mempool_stats']['funded_txo_sum']
        spent = response['chain_stats']['spent_txo_sum'] + \
            response['mempool_stats']['spent_txo_sum']
        return funded - spent

    @classmethod
    def get_balance_testnet(cls, address):
        r = requests.get(cls.TEST_ADDRESS_API.format(
            address), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        funded = response['chain_stats']['funded_txo_sum'] + \
            response['mempool_stats']['funded_txo_sum']
        spent = response['chain_stats']['spent_txo_sum'] + \
            response['mempool_stats']['spent_txo_sum']
        return funded - spent

    @classmethod
    def get_transactions(
        cls, address,
    ):
        #! Blockstream returns at most 50 mempool (unconfirmed) transactions and ignores the rest
        mempool_endpoint = cls.MAIN_ADDRESS_API + '/txs/mempool'

        endpoint = cls.MAIN_ADDRESS_API + '/txs/chain/{}'

        transactions = []

        # Add mempool (unconfirmed) transactions
        r = requests.get(mempool_endpoint.format(
            address), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 400:  # pragma: no cover
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        unconfirmed = [tx['txid'] for tx in response]

        # It is safer to raise exception if API returns exactly 50 unconfirmed
        # transactions, as there could be more that the API is unaware of.
        if len(unconfirmed) == 50:  # pragme: no cover
            raise ExcessiveAddress

        r = requests.get(endpoint.format(address, ''), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 400:  # pragma: no cover
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()

        # The first 25 confirmed transactions are shown with no
        # indication of the number of total transactions.
        total_txs = len(response)

        while total_txs > 0:
            transactions.extend(tx['txid'] for tx in response)

            response = requests.get(endpoint.format(
                address, transactions[-1]), timeout=DEFAULT_TIMEOUT).json()
            total_txs = len(response)

        transactions.extend(unconfirmed)

        return transactions

    @classmethod
    def get_transactions_testnet(cls, address):
        endpoint = cls.TEST_ADDRESS_API + '/txs/chain/{}'

        transactions = []

        r = requests.get(endpoint.format(address, ''), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 400:  # pragma: no cover
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()

        # The first 50 mempool and 25 confirmed transactions are shown with no
        # indication of the number of total transactions.
        total_txs = len(response)

        while total_txs > 0:
            transactions.extend(tx['txid'] for tx in response)

            response = requests.get(endpoint.format(
                address, transactions[-1]), timeout=DEFAULT_TIMEOUT).json()
            total_txs = len(response)

        return transactions

    @classmethod
    def get_transaction_by_id(cls, txid):
        r = requests.get(cls.MAIN_TX_API.format(txid), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.text

    @classmethod
    def get_transaction_by_id_testnet(cls, txid):
        r = requests.get(cls.TEST_TX_API.format(txid), timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.text

    @classmethod
    def get_unspent(cls, address):
        # Get current block height:
        r_block = requests.get(cls.MAIN_ENDPOINT +
                               'blocks/tip/height', timeout=DEFAULT_TIMEOUT)
        if r_block.status_code != 200:  # pragma: no cover
            raise ConnectionError
        block_height = int(r_block.text)

        r = requests.get(cls.MAIN_UNSPENT_API.format(
            address), timeout=DEFAULT_TIMEOUT)

        #! BlockstreamAPI blocks addresses with "too many" UTXOs.
        if r.status_code == 400 and r.text == "Too many history entries":
            raise ExcessiveAddress
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        script_pubkey = bytes_to_hex(address_to_scriptpubkey(address))

        return sorted(
            [
                Unspent(
                    tx["value"],
                    block_height - tx["status"]["block_height"] +
                    1 if tx["status"]["confirmed"] else 0,
                    script_pubkey,
                    tx["txid"],
                    tx["vout"],
                )
                for tx in r.json()
            ],
            key=lambda u: u.confirmations,
        )

    @classmethod
    def get_unspent_testnet(cls, address):
        # Get current block height:
        r_block = requests.get(cls.TEST_ENDPOINT +
                               'blocks/tip/height', timeout=DEFAULT_TIMEOUT)
        if r_block.status_code != 200:  # pragma: no cover
            raise ConnectionError
        block_height = int(r_block.text)

        r = requests.get(cls.TEST_UNSPENT_API.format(
            address), timeout=DEFAULT_TIMEOUT)

        if r.status_code == 400:  # pragma: no cover
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        script_pubkey = bytes_to_hex(address_to_scriptpubkey(address))

        return [
            Unspent(
                tx["value"],
                block_height - tx["status"]["block_height"] +
                1 if tx["status"]["confirmed"] else 0,
                script_pubkey,
                tx["txid"],
                tx["vout"],
            )
            for tx in r.json()
        ]

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.MAIN_TX_PUSH_API, data={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False

    @classmethod
    def broadcast_tx_testnet(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.TEST_TX_PUSH_API, data={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False


class SmartbitAPI:
    MAIN_ENDPOINT = 'https://api.smartbit.com.au/v1/blockchain/'
    MAIN_ADDRESS_API = MAIN_ENDPOINT + 'address/{}'
    MAIN_UNSPENT_API = MAIN_ADDRESS_API + '/unspent'
    MAIN_TX_PUSH_API = MAIN_ENDPOINT + 'pushtx'
    MAIN_TX_API = MAIN_ENDPOINT + 'tx/{}/hex'
    TEST_ENDPOINT = 'https://testnet-api.smartbit.com.au/v1/blockchain/'
    TEST_ADDRESS_API = TEST_ENDPOINT + 'address/{}'
    TEST_UNSPENT_API = TEST_ADDRESS_API + '/unspent'
    TEST_TX_PUSH_API = TEST_ENDPOINT + 'pushtx'
    TEST_TX_API = TEST_ENDPOINT + 'tx/{}/hex'
    TX_PUSH_PARAM = 'hex'

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.MAIN_ADDRESS_API.format(address), params={
                         'limit': '1'}, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['address']['total']['balance_int']

    @classmethod
    def get_balance_testnet(cls, address):
        r = requests.get(cls.TEST_ADDRESS_API.format(address), params={
                         'limit': '1'}, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['address']['total']['balance_int']

    @classmethod
    def get_transactions(cls, address):
        txs_per_page = 1000
        payload = {'limit': str(txs_per_page)}
        r = requests.get(cls.MAIN_ADDRESS_API.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()['address']

        transactions = []
        next_link = None

        if 'transactions' in response:
            transactions.extend(t['txid'] for t in response['transactions'])
            next_link = response['transaction_paging']['next_link']

        while next_link:
            r = requests.get(next_link, timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['address']
            transactions.extend(t['txid'] for t in response['transactions'])
            next_link = response['transaction_paging']['next_link']

        return transactions

    @classmethod
    def get_transaction_by_id(cls, txid):
        r = requests.get(cls.MAIN_TX_API.format(txid) +
                         '?limit=1000', timeout=DEFAULT_TIMEOUT)
        if r.status_code == 400:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['hex'][0]['hex']

    @classmethod
    def get_transactions_testnet(cls, address):
        txs_per_page = 1000
        payload = {'limit': str(txs_per_page)}
        r = requests.get(cls.TEST_ADDRESS_API.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()['address']

        transactions = []
        next_link = None

        if 'transactions' in response:
            transactions.extend(t['txid'] for t in response['transactions'])
            next_link = response['transaction_paging']['next_link']

        while next_link:
            r = requests.get(next_link, params=payload,
                             timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()['address']
            transactions.extend(t['txid'] for t in response['transactions'])
            next_link = response['transaction_paging']['next_link']

        return transactions

    @classmethod
    def get_transaction_by_id_testnet(cls, txid):
        r = requests.get(cls.TEST_TX_API.format(txid) +
                         '?limit=1000', timeout=DEFAULT_TIMEOUT)
        if r.status_code == 400:  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['hex'][0]['hex']

    @classmethod
    def get_unspent(cls, address):
        txs_per_page = 1000
        payload = {'limit': str(txs_per_page)}
        r = requests.get(cls.MAIN_UNSPENT_API.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()

        unspents = []
        next_link = None

        if 'unspent' in response:
            unspents.extend(
                Unspent(
                    currency_to_satoshi(tx['value'], 'btc'),
                    tx['confirmations'],
                    tx['script_pub_key']['hex'],
                    tx['txid'],
                    tx['n'],
                )
                for tx in response['unspent']
            )
            next_link = response['paging']['next_link']

        while next_link:
            r = requests.get(next_link, params=payload,
                             timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()
            unspents.extend(
                Unspent(
                    currency_to_satoshi(tx['value'], 'btc'),
                    tx['confirmations'],
                    tx['script_pub_key']['hex'],
                    tx['txid'],
                    tx['n'],
                )
                for tx in response['unspent']
            )
            next_link = response['paging']['next_link']

        return unspents

    @classmethod
    def get_unspent_testnet(cls, address):
        txs_per_page = 1000
        payload = {'limit': str(txs_per_page)}
        r = requests.get(cls.TEST_UNSPENT_API.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        response = r.json()

        unspents = []
        next_link = None

        if 'unspent' in response:
            unspents.extend(
                Unspent(
                    currency_to_satoshi(tx['value'], 'btc'),
                    tx['confirmations'],
                    tx['script_pub_key']['hex'],
                    tx['txid'],
                    tx['n'],
                )
                for tx in response['unspent']
            )
            next_link = response['paging']['next_link']

        while next_link:
            r = requests.get(next_link, params=payload,
                             timeout=DEFAULT_TIMEOUT)
            if r.status_code != 200:  # pragma: no cover
                raise ConnectionError
            response = r.json()
            unspents.extend(
                Unspent(
                    currency_to_satoshi(tx['value'], 'btc'),
                    tx['confirmations'],
                    tx['script_pub_key']['hex'],
                    tx['txid'],
                    tx['n'],
                )
                for tx in response['unspent']
            )
            next_link = response['paging']['next_link']

        return unspents

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.MAIN_TX_PUSH_API, json={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False

    @classmethod
    def broadcast_tx_testnet(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.TEST_TX_PUSH_API, json={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        print(r.json())
        return True if r.status_code == 200 else False


class BlockchainAPI:
    ENDPOINT = 'https://blockchain.info/'
    ADDRESS_API = ENDPOINT + 'address/{}?format=json'
    UNSPENT_API = ENDPOINT + 'unspent'
    TX_PUSH_API = ENDPOINT + 'pushtx'
    TX_API = ENDPOINT + 'rawtx/'
    TX_PUSH_PARAM = 'tx'

    @classmethod
    def get_balance(cls, address):
        r = requests.get(cls.ADDRESS_API.format(address) +
                         '&limit=0', timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.json()['final_balance']

    @classmethod
    def get_transactions(cls, address):
        endpoint = cls.ADDRESS_API

        transactions = []
        offset = 0
        txs_per_page = 50
        payload = {'offset': str(offset)}

        r = requests.get(endpoint.format(address),
                         params=payload, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        response = r.json()
        total_txs = response['n_tx']

        while total_txs > 0:
            transactions.extend(tx['hash'] for tx in response['txs'])

            total_txs -= txs_per_page
            offset += txs_per_page
            payload['offset'] = str(offset)
            response = requests.get(endpoint.format(
                address), params=payload, timeout=DEFAULT_TIMEOUT).json()

        return transactions

    @classmethod
    def get_transaction_by_id(cls, txid):
        r = requests.get(cls.TX_API + txid +
                         '?limit=0&format=hex', timeout=DEFAULT_TIMEOUT)
        if r.status_code == 500 and r.text == 'Transaction not found':  # pragma: no cover
            return None
        if r.status_code != 200:  # pragma: no cover
            raise ConnectionError
        return r.text

    @classmethod
    def get_unspent(cls, address):
        endpoint = cls.UNSPENT_API

        offset = 0
        utxos_per_page = 1000
        payload = {'active': address, 'offset': str(
            offset), 'limit': str(utxos_per_page)}

        r = requests.get(endpoint, params=payload, timeout=DEFAULT_TIMEOUT)

        if r.status_code == 500:  # pragma: no cover
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        unspents = [
            Unspent(tx['value'], tx['confirmations'], tx['script'],
                    tx['tx_hash_big_endian'], tx['tx_output_n'])
            for tx in r.json()['unspent_outputs']
        ]

        #! BlockchainAPI only supports up to 1000 UTXOs.
        #! Raises an exception for addresses that may contain more UTXOs.
        if len(unspents) == 1000:
            raise ExcessiveAddress

        return unspents[::-1]

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        r = requests.post(cls.TX_PUSH_API, data={
                          cls.TX_PUSH_PARAM: tx_hex}, timeout=DEFAULT_TIMEOUT)
        return True if r.status_code == 200 else False


class NetworkAPI:
    IGNORED_ERRORS = (
        requests.exceptions.RequestException,
        requests.exceptions.HTTPError,
        requests.exceptions.ConnectionError,
        requests.exceptions.ProxyError,
        requests.exceptions.SSLError,
        requests.exceptions.Timeout,
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ReadTimeout,
        requests.exceptions.TooManyRedirects,
        requests.exceptions.ChunkedEncodingError,
        requests.exceptions.ContentDecodingError,
        requests.exceptions.StreamConsumedError,
    )

    # Mainnet
    GET_BALANCE_MAIN = [BitcoinDotComAPI.get_balance,
                        BitcoreAPI.get_balance]
    GET_BALANCE_MAIN_BTC = [BitcoreAPI.get_balance_btc,
                            BlockchairAPI.get_balance,
                            SmartbitAPI.get_balance,
                            BlockchainAPI.get_balance,
                            BlockstreamAPI.get_balance]
    GET_TRANSACTIONS_MAIN = [BitcoinDotComAPI.get_transactions,
                             BitcoreAPI.get_transactions]
    GET_TRANSACTIONS_MAIN_BTC = [BitcoreAPI.get_transactions_btc,
                                 BlockchairAPI.get_transactions,  # Limit 1000
                                 SmartbitAPI.get_transactions,  # Limit 1000
                                 BlockchainAPI.get_transactions,  # No limit, requires multiple requests
                                 BlockstreamAPI.get_transactions,  # Limit 1000
                                 ]

    GET_UNSPENT_MAIN = [BitcoinDotComAPI.get_unspent,
                        BitcoreAPI.get_unspent]
    GET_UNSPENT_MAIN_BTC = [BitcoreAPI.get_unspent_btc,
                            ]
    BROADCAST_TX_MAIN = [BitcoinDotComAPI.broadcast_tx]

    BROADCAST_TX_MAIN_BTC = [BlockchairAPI.broadcast_tx,
                             SmartbitAPI.broadcast_tx,  # Limit 5/minute
                             BlockchainAPI.broadcast_tx,
                             BlockstreamAPI.broadcast_tx, ]

    GET_TX_MAIN = [BitcoinDotComAPI.get_transaction,
                   BitcoreAPI.get_transaction]

    GET_TX_MAIN_BTC = [BitcoreAPI.get_transaction_btc,
                       BlockchairAPI.get_transaction_by_id,
                       SmartbitAPI.get_transaction_by_id,
                       BlockchainAPI.get_transaction_by_id,
                       BlockstreamAPI.get_transaction_by_id, ]
    GET_TX_AMOUNT_MAIN = [BitcoinDotComAPI.get_tx_amount]
    GET_RAW_TX_MAIN = [BitcoinDotComAPI.get_raw_transaction]

    GET_BALANCE_TEST = [
        BlockchairAPI.get_balance_testnet,
        BlockstreamAPI.get_balance_testnet,
        SmartbitAPI.get_balance_testnet,
    ]
    GET_TRANSACTIONS_TEST = [
        SmartbitAPI.get_transactions_testnet,  # Limit 1000
        BlockchairAPI.get_transactions_testnet,  # Limit 1000
        BlockstreamAPI.get_transactions_testnet,
    ]
    GET_TRANSACTION_BY_ID_TEST = [
        SmartbitAPI.get_transaction_by_id_testnet,
        BlockchairAPI.get_transaction_by_id_testnet,
        BlockstreamAPI.get_transaction_by_id_testnet,
    ]
    GET_UNSPENT_TEST_BTC = [
        SmartbitAPI.get_unspent_testnet,  # Limit 1000
        BlockchairAPI.get_unspent_testnet,
        BlockstreamAPI.get_unspent_testnet,
    ]
    BROADCAST_TX_TEST = [
        BlockstreamAPI.broadcast_tx_testnet,
        BlockchairAPI.broadcast_tx_testnet,
        SmartbitAPI.broadcast_tx_testnet,  # Limit 5/minute
    ]

    @classmethod
    def get_balance(cls, address):
        """Gets the balance of an address in satoshi.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``int``
        """

        for api_call in cls.GET_BALANCE_MAIN:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_balance_btc(cls, address):
        """Gets the balance of an address in satoshi.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``int``
        """

        for api_call in cls.GET_BALANCE_MAIN_BTC:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_balance_testnet(cls, address):
        """Gets the balance of an address on the test network in satoshi.
        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``int``
        """

        for api_call in cls.GET_BALANCE_TEST:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transactions(cls, address):
        """Gets the ID of all transactions related to an address.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of ``str``
        """

        for api_call in cls.GET_TRANSACTIONS_MAIN:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transactions_btc(cls, address):
        """Gets the ID of all transactions related to an address.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of ``str``
        """

        for api_call in cls.GET_TRANSACTIONS_MAIN_BTC:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transactions_testnet(cls, address):
        """Gets the ID of all transactions related to an address on the test
        network.
        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of ``str``
        """

        for api_call in cls.GET_TRANSACTIONS_TEST:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transaction(cls, txid):
        """Gets the full transaction details.

        :param txid: The transaction id in question.
        :type txid: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``Transaction``
        """

        for api_call in cls.GET_TX_MAIN:
            try:
                return api_call(txid)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transaction_btc(cls, txid):
        """Gets the full transaction details.

        :param txid: The transaction id in question.
        :type txid: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``Transaction``
        """

        for api_call in cls.GET_TX_MAIN_BTC:
            try:
                return api_call(txid)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_transaction_testnet(cls, txid):
        """Gets a raw transaction hex by its transaction id (txid) on the test.
        :param txid: The id of the transaction
        :type txid: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``string``
        """

        for api_call in cls.GET_TRANSACTION_BY_ID_TEST:
            try:
                return api_call(txid)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_tx_amount(cls, txid, txindex):
        """Gets the amount of a given transaction output.

        :param txid: The transaction id in question.
        :type txid: ``str``
        :param txindex: The transaction index in question.
        :type txindex: ``int``
        :raises ConnectionError: If all API services fail.
        :rtype: ``Decimal``
        """

        for api_call in cls.GET_TX_AMOUNT_MAIN:
            try:
                return api_call(txid, txindex)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_unspent(cls, address):
        """Gets all unspent transaction outputs belonging to an address.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of :class:`~bitcash.network.meta.Unspent`
        """

        for api_call in cls.GET_UNSPENT_MAIN:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_unspent_btc(cls, address):
        """Gets all unspent transaction outputs belonging to an address.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of :class:`~bitcash.network.meta.Unspent`
        """

        for api_call in cls.GET_UNSPENT_MAIN_BTC:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_unspent_testnet_btc(cls, address):
        """Gets all unspent transaction outputs belonging to an address on the
        test network.
        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of :class:`~bit.network.meta.Unspent`
        """

        for api_call in cls.GET_UNSPENT_TEST_BTC:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def get_raw_transaction(cls, txid):
        """Gets the raw, unparsed transaction details.

        :param txid: The transaction id in question.
        :type txid: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``Transaction``
        """

        for api_call in cls.GET_RAW_TX_MAIN:
            try:
                return api_call(txid)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def broadcast_tx(cls, tx_hex):  # pragma: no cover
        """Broadcasts a transaction to the blockchain.

        :param tx_hex: A signed transaction in hex form.
        :type tx_hex: ``str``
        :raises ConnectionError: If all API services fail.
        """
        success = None

        for api_call in cls.BROADCAST_TX_MAIN:
            try:
                success = api_call(tx_hex)
                if not success:
                    continue
                return
            except cls.IGNORED_ERRORS:
                pass

        if success is False:
            raise ConnectionError('Transaction broadcast failed, or '
                                  'Unspents were already used.')

        raise ConnectionError('All APIs are unreachable.')

    @classmethod
    def broadcast_tx_testnet(cls, tx_hex):  # pragma: no cover
        """Broadcasts a transaction to the test network's blockchain.
        :param tx_hex: A signed transaction in hex form.
        :type tx_hex: ``str``
        :raises ConnectionError: If all API services fail.
        """
        success = None

        for api_call in cls.BROADCAST_TX_TEST:
            try:
                success = api_call(tx_hex)
                if not success:
                    continue
                return
            except cls.IGNORED_ERRORS:
                pass

        if success is False:
            raise ConnectionError(
                'Transaction broadcast failed, or Unspents were already used.')

        raise ConnectionError('All APIs are unreachable.')
