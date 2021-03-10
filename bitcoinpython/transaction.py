import logging
from collections import namedtuple
from itertools import islice
from cashaddress import convert as cashaddress
from bitcoinpython.base58 import b58decode_check
from bitcoinpython.base32 import decode as segwit_decode
from bitcoinpython.crypto import double_sha256, sha256
from bitcoinpython.exceptions import InsufficientFunds
from bitcoinpython.format import address_to_public_key_hash, get_version, segwit_scriptpubkey, verify_sig
from bitcoinpython.network.rates import currency_to_satoshi_cached
from bitcoinpython.utils import (
    bytes_to_hex, chunk_data, hex_to_bytes, int_to_unknown_bytes, int_to_varint,
    script_push,
    get_signatures_from_script,
    read_bytes,
    read_var_int,
    read_var_string,
    read_segwit_string,
)
from bitcoinpython.constants import (
    TEST_SCRIPT_HASH,
    MAIN_SCRIPT_HASH,
    TEST_PUBKEY_HASH,
    MAIN_PUBKEY_HASH,
    VERSION_1,
    MARKER,
    FLAG,
    SEQUENCE,
    LOCK_TIME,
    HASH_TYPE,
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_PUSH_20,
    OP_RETURN,
    OP_EQUAL,
    MESSAGE_LIMIT,
)


VERSION_1 = 0x01.to_bytes(4, byteorder='little')
SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
LOCK_TIME = 0x00.to_bytes(4, byteorder='little')

##
# Python 3 doesn't allow bitwise operators on byte objects...
HASH_TYPE = 0x01.to_bytes(4, byteorder='little')
# BitcoinCash fork ID.
SIGHASH_FORKID = 0x40.to_bytes(4, byteorder='little')
# So we just do this for now. FIXME
HASH_TYPE = 0x41.to_bytes(4, byteorder='little')
##

OP_0 = b'\x00'
OP_CHECKLOCKTIMEVERIFY = b'\xb1'
OP_CHECKSIG = b'\xac'
OP_DUP = b'v'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'
OP_PUSH_20 = b'\x14'
OP_RETURN = b'\x6a'
OP_PUSHDATA1 = b'\x4c'
OP_PUSHDATA2 = b'\x4d'
OP_PUSHDATA4 = b'\x4e'

MESSAGE_LIMIT = 220


class TxIn:
    __slots__ = ('script', 'script_len', 'txid', 'txindex', 'amount')

    def __init__(self, script, script_len, txid, txindex, amount):
        self.script = script
        self.script_len = script_len
        self.txid = txid
        self.txindex = txindex
        self.amount = amount

    def __eq__(self, other):
        return (self.script == other.script and
                self.script_len == other.script_len and
                self.txid == other.txid and
                self.txindex == other.txindex and
                self.amount == other.amount)

    def __repr__(self):
        return 'TxIn({}, {}, {}, {}, {})'.format(
            repr(self.script),
            repr(self.script_len),
            repr(self.txid),
            repr(self.txindex),
            repr(self.amount)
        )


Output = namedtuple('Output', ('address', 'amount', 'currency'))


def calc_txid(tx_hex):
    return bytes_to_hex(double_sha256(hex_to_bytes(tx_hex))[::-1])


def estimate_tx_fee(n_in, n_out, satoshis, compressed, op_return_size=0):

    if not satoshis:
        return 0

    estimated_size = (
        4 +  # version
        n_in * (148 if compressed else 180)
        + len(int_to_unknown_bytes(n_in, byteorder='little'))
        + n_out * 34  # excluding op_return outputs, dealt with separately
        + len(int_to_unknown_bytes(n_out, byteorder='little'))
        # grand total size of op_return outputs(s) and related field(s)
        + op_return_size
        + 4  # time lock
    )

    estimated_fee = estimated_size * satoshis

    logging.debug('Estimated fee: {} satoshis for {} bytes'.format(
        estimated_fee, estimated_size))

    return estimated_fee


def get_op_return_size(message, custom_pushdata=False):
    # calculate op_return size for each individual message
    if custom_pushdata is False:
        op_return_size = (
            8  # int64_t amount 0x00000000
            + len(OP_RETURN)  # 1 byte
            # 1 byte if <75 bytes, 2 bytes if OP_PUSHDATA1...
            + len(get_op_pushdata_code(message))
            + len(message)  # Max 220 bytes at present
        )

    if custom_pushdata is True:
        op_return_size = (
            8  # int64_t amount 0x00000000
            + len(OP_RETURN)  # 1 byte
            # Unsure if Max size will be >220 bytes due to extra OP_PUSHDATA codes...
            + len(message)
        )

    # "Var_Int" that preceeds OP_RETURN - 0xdf is max value with current 220 byte limit (so only adds 1 byte)
    op_return_size += len(int_to_varint(op_return_size))
    return op_return_size


def get_op_pushdata_code(dest):
    length_data = len(dest)
    if length_data <= 0x4c:  # (https://en.bitcoin.it/wiki/Script)
        return length_data.to_bytes(1, byteorder='little')
    elif length_data <= 0xff:
        # OP_PUSHDATA1 format
        return OP_PUSHDATA1 + length_data.to_bytes(1, byteorder='little')
    elif length_data <= 0xffff:
        # OP_PUSHDATA2 format
        return OP_PUSHDATA2 + length_data.to_bytes(2, byteorder='little')
    else:
        # OP_PUSHDATA4 format
        return OP_PUSHDATA4 + length_data.to_bytes(4, byteorder='little')


def sanitize_tx_data(unspents, outputs, fee, leftover, combine=True, message=None, compressed=True, custom_pushdata=False):
    """
    sanitize_tx_data()

    fee is in satoshis per byte.
    """

    outputs = outputs.copy()

    for i, output in enumerate(outputs):
        dest, amount, currency = output
        outputs[i] = (dest, currency_to_satoshi_cached(amount, currency))

    if not unspents:
        raise ValueError('Transactions must have at least one unspent.')

    # Temporary storage so all outputs precede messages.
    messages = []
    total_op_return_size = 0

    if message and (custom_pushdata is False):
        try:
            message = message.encode('utf-8')
        except AttributeError:
            pass  # assume message is already a bytes-like object

        message_chunks = chunk_data(message, MESSAGE_LIMIT)

        for message in message_chunks:
            messages.append((message, 0))
            total_op_return_size += get_op_return_size(
                message, custom_pushdata=False)

    elif message and (custom_pushdata is True):
        if (len(message) >= 220):
            # FIXME add capability for >220 bytes for custom pushdata elements
            raise ValueError(
                "Currently cannot exceed 220 bytes with custom_pushdata.")
        else:
            messages.append((message, 0))
            total_op_return_size += get_op_return_size(
                message, custom_pushdata=True)

    # Include return address in fee estimate.
    total_in = 0
    num_outputs = len(outputs) + 1
    sum_outputs = sum(out[1] for out in outputs)

    if combine:
        # calculated_fee is in total satoshis.
        calculated_fee = estimate_tx_fee(
            len(unspents), num_outputs, fee, compressed, total_op_return_size)
        total_out = sum_outputs + calculated_fee
        unspents = unspents.copy()
        total_in += sum(unspent.amount for unspent in unspents)

    else:
        unspents = sorted(unspents, key=lambda x: x.amount)

        index = 0

        for index, unspent in enumerate(unspents):
            total_in += unspent.amount
            calculated_fee = estimate_tx_fee(
                len(unspents[:index + 1]), num_outputs, fee, compressed, total_op_return_size)
            total_out = sum_outputs + calculated_fee

            if total_in >= total_out:
                break

        unspents[:] = unspents[:index + 1]

    remaining = total_in - total_out

    if remaining > 0:
        outputs.append((leftover, remaining))
    elif remaining < 0:
        raise InsufficientFunds('Balance {} is less than {} (including '
                                'fee).'.format(total_in, total_out))

    outputs.extend(messages)

    return unspents, outputs


def construct_output_block(outputs, custom_pushdata=False):

    output_block = b''

    for data in outputs:
        dest, amount = data

        # Real recipient
        if amount:
            script = (OP_DUP + OP_HASH160 + OP_PUSH_20 +
                      address_to_public_key_hash(dest) +
                      OP_EQUALVERIFY + OP_CHECKSIG)

            output_block += amount.to_bytes(8, byteorder='little')

        # Blockchain storage
        else:
            if custom_pushdata is False:
                script = OP_RETURN + get_op_pushdata_code(dest) + dest

                output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

            elif custom_pushdata is True:
                # manual control over number of bytes in each batch of pushdata
                if type(dest) != bytes:
                    raise TypeError("custom pushdata must be of type: bytes")
                else:
                    script = (OP_RETURN + dest)

                output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

        # Script length in wiki is "Var_int" but there's a note of "modern BitcoinQT" using a more compact "CVarInt"
        # CVarInt is what I believe we have here - No changes made. If incorrect - only breaks if 220 byte limit is increased.
        output_block += int_to_unknown_bytes(len(script), byteorder='little')
        output_block += script

    return output_block


def construct_input_block(inputs):

    input_block = b''
    sequence = SEQUENCE

    for txin in inputs:
        input_block += (
            txin.txid +
            txin.txindex +
            txin.script_len +
            txin.script +
            sequence
        )

    return input_block


def create_p2pkh_transaction(private_key, unspents, outputs, custom_pushdata=False):

    public_key = private_key.public_key
    public_key_len = len(public_key).to_bytes(1, byteorder='little')

    scriptCode = private_key.scriptcode
    scriptCode_len = int_to_varint(len(scriptCode))

    version = VERSION_1
    lock_time = LOCK_TIME
    # sequence = SEQUENCE
    hash_type = HASH_TYPE
    input_count = int_to_unknown_bytes(len(unspents), byteorder='little')
    output_count = int_to_unknown_bytes(len(outputs), byteorder='little')

    output_block = construct_output_block(
        outputs, custom_pushdata=custom_pushdata)

    # Optimize for speed, not memory, by pre-computing values.
    inputs = []
    for unspent in unspents:
        script = hex_to_bytes(unspent.script)
        script_len = int_to_unknown_bytes(len(script), byteorder='little')
        txid = hex_to_bytes(unspent.txid)[::-1]
        txindex = unspent.txindex.to_bytes(4, byteorder='little')
        amount = unspent.amount.to_bytes(8, byteorder='little')

        inputs.append(TxIn(script, script_len, txid, txindex, amount))

    hashPrevouts = double_sha256(b''.join([i.txid+i.txindex for i in inputs]))
    hashSequence = double_sha256(b''.join([SEQUENCE for i in inputs]))
    hashOutputs = double_sha256(output_block)

    # scriptCode_len is part of the script.
    for i, txin in enumerate(inputs):
        to_be_hashed = (
            version +
            hashPrevouts +
            hashSequence +
            txin.txid +
            txin.txindex +
            scriptCode_len +
            scriptCode +
            txin.amount +
            SEQUENCE +
            hashOutputs +
            lock_time +
            hash_type
        )
        hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin Cash

        # signature = private_key.sign(hashed) + b'\x01'
        signature = private_key.sign(hashed) + b'\x41'

        script_sig = (
            len(signature).to_bytes(1, byteorder='little') +
            signature +
            public_key_len +
            public_key
        )

        inputs[i].script = script_sig
        inputs[i].script_len = int_to_unknown_bytes(
            len(script_sig), byteorder='little')

    return bytes_to_hex(
        version +
        input_count +
        construct_input_block(inputs) +
        output_count +
        output_block +
        lock_time
    )


def address_to_scriptpubkey(address):
    # Raise ValueError if we cannot identify the address.
    get_version(address)
    try:
        version = b58decode_check(address)[:1]
    except ValueError:
        witver, data = segwit_decode(address)
        return segwit_scriptpubkey(witver, data)

    if version == MAIN_PUBKEY_HASH or version == TEST_PUBKEY_HASH:
        return OP_DUP + OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(address) + OP_EQUALVERIFY + OP_CHECKSIG
    elif version == MAIN_SCRIPT_HASH or version == TEST_SCRIPT_HASH:
        return OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(address) + OP_EQUAL


class TxOut:
    __slots__ = ('amount', 'script_pubkey_len', 'script_pubkey')

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey
        self.script_pubkey_len = int_to_varint(len(script_pubkey))

    def __eq__(self, other):
        return (
            self.amount == other.amount
            and self.script_pubkey == other.script_pubkey
            and self.script_pubkey_len == other.script_pubkey_len
        )

    def __repr__(self):
        return 'TxOut({}, {}, {})'.format(repr(self.amount), repr(self.script_pubkey), repr(self.script_pubkey_len))

    def __bytes__(self):
        return b''.join([self.amount, self.script_pubkey_len, self.script_pubkey])


def construct_outputs(outputs):
    outputs_obj = []

    for data in outputs:
        dest, amount = data

        # P2PKH/P2SH/Bech32
        if amount:
            script_pubkey = address_to_scriptpubkey(dest)

            amount = amount.to_bytes(8, byteorder='little')

        # Blockchain storage
        else:
            script_pubkey = OP_RETURN + \
                len(dest).to_bytes(1, byteorder='little') + dest

            amount = b'\x00\x00\x00\x00\x00\x00\x00\x00'

        outputs_obj.append(TxOut(amount, script_pubkey))

    return outputs_obj


class TxInn:
    __slots__ = ('script_sig', 'script_sig_len', 'txid', 'txindex',
                 'witness', 'amount', 'sequence', 'segwit_input')

    def __init__(self, script_sig, txid, txindex, witness=b'', amount=None, sequence=SEQUENCE, segwit_input=False):

        self.script_sig = script_sig
        self.script_sig_len = int_to_varint(len(script_sig))
        self.txid = txid
        self.txindex = txindex
        self.witness = witness
        self.amount = amount
        self.sequence = sequence
        self.segwit_input = segwit_input

    def __eq__(self, other):
        return (
            self.script_sig == other.script_sig
            and self.script_sig_len == other.script_sig_len
            and self.txid == other.txid
            and self.txindex == other.txindex
            and self.witness == other.witness
            and self.amount == other.amount
            and self.sequence == other.sequence
            and self.segwit_input == other.segwit_input
        )

    def __repr__(self):
        if self.is_segwit():
            return 'TxIn({}, {}, {}, {}, {}, {}, {})'.format(
                repr(self.script_sig),
                repr(self.script_sig_len),
                repr(self.txid),
                repr(self.txindex),
                repr(self.witness),
                repr(self.amount),
                repr(self.sequence),
            )
        return 'TxIn({}, {}, {}, {}, {})'.format(
            repr(self.script_sig), repr(self.script_sig_len), repr(
                self.txid), repr(self.txindex), repr(self.sequence)
        )

    def __bytes__(self):
        return b''.join([self.txid, self.txindex, self.script_sig_len, self.script_sig, self.sequence])

    def is_segwit(self):
        return self.segwit_input or self.witness


class TxObj:
    __slots__ = ('version', 'TxIn', 'TxOut', 'locktime')

    def __init__(self, version, TxIn, TxOut, locktime):
        segwit_tx = any([i.segwit_input or i.witness for i in TxIn])
        self.version = version
        self.TxIn = TxIn
        if segwit_tx:
            for i in self.TxIn:
                i.witness = i.witness if i.witness else b'\x00'
        self.TxOut = TxOut
        self.locktime = locktime

    def __eq__(self, other):
        return (
            self.version == other.version
            and self.TxIn == other.TxIn
            and self.TxOut == other.TxOut
            and self.locktime == other.locktime
        )

    def __repr__(self):
        return 'TxObj({}, {}, {}, {})'.format(
            repr(self.version), repr(self.TxIn), repr(
                self.TxOut), repr(self.locktime)
        )

    def __bytes__(self):
        inp = int_to_varint(len(self.TxIn)) + b''.join(map(bytes, self.TxIn))
        out = int_to_varint(len(self.TxOut)) + b''.join(map(bytes, self.TxOut))
        wit = b''.join([w.witness for w in self.TxIn])
        return b''.join([self.version, MARKER if wit else b'', FLAG if wit else b'', inp, out, wit, self.locktime])

    def legacy_repr(self):
        inp = int_to_varint(len(self.TxIn)) + b''.join(map(bytes, self.TxIn))
        out = int_to_varint(len(self.TxOut)) + b''.join(map(bytes, self.TxOut))
        return b''.join([self.version, inp, out, self.locktime])

    def to_hex(self):
        return bytes_to_hex(bytes(self))

    @classmethod
    def is_segwit(cls, tx):
        if isinstance(tx, cls):
            tx = bytes(tx)
        elif not isinstance(tx, bytes):
            tx = hex_to_bytes(tx)
        return tx[4:6] == MARKER + FLAG


def sign_tx(private_key, tx, *, unspents):
    """Signs inputs in provided transaction object for which unspents
    are provided and can be signed by the private key.
    :param private_key: Private key
    :type private_key: ``PrivateKey`` or ``MultiSig``
    :param tx: Transaction object
    :type tx: ``TxObj``
    :param unspents: For inputs to be signed their corresponding Unspent objects
                     must be provided.
    :type unspents: ``list`` of :class:`~bit.network.meta.Unspent`
    :returns: The signed transaction as hex.
    :rtype: ``str``
    """

    # input_dict contains those unspents that can be signed by private_key,
    # providing additional information for segwit-inputs (the amount to spend)
    input_dict = {}
    try:
        for unspent in unspents:
            if not private_key.can_sign_unspent(unspent):
                continue
            tx_input = hex_to_bytes(unspent.txid)[
                ::-1] + unspent.txindex.to_bytes(4, byteorder='little')
            input_dict[tx_input] = unspent.to_dict()
    except TypeError:
        raise TypeError(
            'Please provide as unspents at least all inputs to be signed with the function call in a list.'
        )

    # Determine input indices to sign from input_dict (allows for transaction batching)
    sign_inputs = [j for j, i in enumerate(
        tx.TxIn) if i.txid + i.txindex in input_dict]

    segwit_tx = TxObj.is_segwit(tx)
    public_key = private_key.public_key
    public_key_push = script_push(len(public_key))
    hash_type = HASH_TYPE

    # Make input parameters for preimage calculation
    inputs_parameters = []

    # The TxObj in `tx` will below be modified to contain the scriptCodes used
    # for the transaction structure to be signed

    # `input_script_field` copies the scriptSigs for partially signed
    # transactions to later extract signatures from it:
    input_script_field = [tx.TxIn[i].script_sig for i in range(len(tx.TxIn))]

    for i in sign_inputs:
        # Create transaction object for preimage calculation
        tx_input = tx.TxIn[i].txid + tx.TxIn[i].txindex
        segwit_input = input_dict[tx_input]['segwit']
        tx.TxIn[i].segwit_input = segwit_input

        script_code = private_key.scriptcode
        script_code_len = int_to_varint(len(script_code))

        # Use scriptCode for preimage calculation of transaction object:
        tx.TxIn[i].script_sig = script_code
        tx.TxIn[i].script_sig_len = script_code_len

        if segwit_input:
            try:
                tx.TxIn[i].script_sig += input_dict[tx_input]['amount'].to_bytes(
                    8, byteorder='little')

                # For partially signed Segwit transactions the signatures must
                # be extracted from the witnessScript field:
                input_script_field[i] = tx.TxIn[i].witness
            except AttributeError:
                raise ValueError(
                    'Cannot sign a segwit input when the input\'s amount is '
                    'unknown. Maybe no network connection or the input is '
                    'already spent? Then please provide all inputs to sign as '
                    '`Unspent` objects to the function call.'
                )

        inputs_parameters.append([i, hash_type, segwit_input])
    preimages = calculate_preimages(tx, inputs_parameters)

    # Calculate signature scripts:
    for hash, (i, _, segwit_input) in zip(preimages, inputs_parameters):
        signature = private_key.sign(hash) + b'\x01'

        # ------------------------------------------------------------------
        if private_key.instance == 'MultiSig' or private_key.instance == 'MultiSigTestnet':
            # P2(W)SH input

            script_blob = b''
            sigs = {}
            # Initial number of witness items (OP_0 + one signature + redeemscript).
            witness_count = 3
            if input_script_field[i]:
                sig_list = get_signatures_from_script(input_script_field[i])
                # Bitcoin Core convention: Every missing signature is denoted
                # by 0x00. Only used for already partially-signed scriptSigs:
                script_blob += b'\x00' * (private_key.m - len(sig_list) - 1)
                # Total number of witness items when partially or fully signed:
                witness_count = private_key.m + 2
                # For a partially signed input make a dictionary containing
                # all the provided signatures with public-keys as keys:
                for sig in sig_list:
                    for pub in private_key.public_keys:
                        if verify_sig(sig[:-1], hash, pub):
                            # If we already found a valid signature for pubkey
                            # we just overwrite it and don't care.
                            sigs[pub] = sig
                if len(sigs) >= private_key.m:
                    raise ValueError(
                        'Transaction is already signed with sufficiently needed signatures.')

            sigs[public_key] = signature

            witness = b''
            # Sort ingthe signatures according to the public-key list:
            for pub in private_key.public_keys:
                if pub in sigs:
                    sig = sigs[pub]
                    length = int_to_varint(
                        len(sig)) if segwit_input else script_push(len(sig))
                    witness += length + sig

            script_sig = b'\x22' + private_key.segwit_scriptcode

            witness = (int_to_varint(witness_count)
                       if segwit_input else b'') + b'\x00' + witness + script_blob
            witness += (
                int_to_varint(len(private_key.redeemscript))
                if segwit_input
                else script_push(len(private_key.redeemscript))
            ) + private_key.redeemscript

            script_sig = script_sig if segwit_input else witness
            witness = witness if segwit_input else b'\x00' if segwit_tx else b''

        # ------------------------------------------------------------------
        else:
            # P2(W)PKH input

            script_sig = b'\x16' + private_key.segwit_scriptcode

            witness = (
                (b'\x02' if segwit_input else b'')
                # witness counter
                + len(signature).to_bytes(1, byteorder='little')
                + signature
                + public_key_push
                + public_key
            )

            script_sig = script_sig if segwit_input else witness
            witness = witness if segwit_input else b'\x00' if segwit_tx else b''

        # Providing the signature(s) to the input
        tx.TxIn[i].script_sig = script_sig
        tx.TxIn[i].script_sig_len = int_to_varint(len(script_sig))
        tx.TxIn[i].witness = witness

    return tx.to_hex()


def create_new_transaction(private_key, unspents, outputs):

    version = VERSION_1
    lock_time = LOCK_TIME
    outputs = construct_outputs(outputs)

    # Optimize for speed, not memory, by pre-computing values.
    inputs = []
    for unspent in unspents:
        script_sig = b''  # empty scriptSig for new unsigned transaction.
        txid = hex_to_bytes(unspent.txid)[::-1]
        txindex = unspent.txindex.to_bytes(4, byteorder='little')
        amount = int(unspent.amount).to_bytes(8, byteorder='little')
        sequence = unspent.sequence.to_bytes(4, byteorder='little')
        inputs.append(TxInn(script_sig, txid, txindex, amount=amount, segwit_input=unspent.segwit,
                            sequence=sequence))

    tx_unsigned = TxObj(version, inputs, outputs, lock_time)

    tx = sign_tx(private_key, tx_unsigned, unspents=unspents)
    return tx


def calculate_preimages(tx_obj, inputs_parameters):
    """Calculates preimages for provided transaction structure and input
    values.
    :param tx_obj: The transaction object used to calculate preimage from using
                   a transaction digest algorithm, such as BIP-143 for Segwit
                   inputs. This transaction object must hence have scriptCodes
                   filled into the corresponding scriptSigs in the inputs.
    :type tx_obj: :object:`~bit.transaction.TxObj`
    :param inputs_parameters: A list of tuples with input index as integer,
                              hash type as integer and a boolean flag to denote
                              if the input is spending from a Segwit output.
                              For example: [(0, 1, True), (2, 1, False), (...)]
    :type inputs_parameters: A `list` of `tuple`
    """

    # Tx object data:
    input_count = int_to_varint(len(tx_obj.TxIn))
    output_count = int_to_varint(len(tx_obj.TxOut))
    output_block = b''.join([bytes(o) for o in tx_obj.TxOut])

    hashPrevouts = double_sha256(
        b''.join([i.txid + i.txindex for i in tx_obj.TxIn]))
    hashSequence = double_sha256(b''.join([i.sequence for i in tx_obj.TxIn]))
    hashOutputs = double_sha256(output_block)

    preimages = []
    for input_index, hash_type, segwit_input in inputs_parameters:
        # We can only handle hashType == 1:
        if hash_type != HASH_TYPE:
            raise ValueError('Bit only support hashType of value 1.')
        # Calculate prehashes:
        if segwit_input:
            # BIP-143 preimage:
            hashed = sha256(
                tx_obj.version
                + hashPrevouts
                + hashSequence
                + tx_obj.TxIn[input_index].txid
                + tx_obj.TxIn[input_index].txindex
                + tx_obj.TxIn[input_index].script_sig_len
                + tx_obj.TxIn[input_index].script_sig  # scriptCode length
                # scriptCode (includes amount)
                + tx_obj.TxIn[input_index].sequence
                + hashOutputs
                + tx_obj.locktime
                + hash_type
            )
        else:
            hashed = sha256(
                tx_obj.version
                + input_count
                + b''.join(ti.txid + ti.txindex + OP_0 +
                           ti.sequence for ti in islice(tx_obj.TxIn, input_index))
                + tx_obj.TxIn[input_index].txid
                + tx_obj.TxIn[input_index].txindex
                + tx_obj.TxIn[input_index].script_sig_len
                + tx_obj.TxIn[input_index].script_sig  # scriptCode length
                + tx_obj.TxIn[input_index].sequence  # scriptCode
                + b''.join(
                    ti.txid + ti.txindex + OP_0 + ti.sequence for ti in islice(tx_obj.TxIn, input_index + 1, None)
                )
                + output_count
                + output_block
                + tx_obj.locktime
                + hash_type
            )
        preimages.append(hashed)
    return preimages


import re
def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        return deserialize(hex_to_bytes(tx))

    segwit_tx = TxObj.is_segwit(tx)

    version, tx = read_bytes(tx, 4)

    if segwit_tx:
        _, tx = read_bytes(tx, 1)  # ``marker`` is nulled
        _, tx = read_bytes(tx, 1)  # ``flag`` is nulled

    ins, tx = read_var_int(tx)
    inputs = []
    for i in range(ins):
        txid, tx = read_bytes(tx, 32)
        txindex, tx = read_bytes(tx, 4)
        script_sig, tx = read_var_string(tx)
        sequence, tx = read_bytes(tx, 4)
        inputs.append(TxInn(script_sig, txid, txindex, sequence=sequence))

    outs, tx = read_var_int(tx)
    outputs = []
    for _ in range(outs):
        amount, tx = read_bytes(tx, 8)
        script_pubkey, tx = read_var_string(tx)
        outputs.append(TxOut(amount, script_pubkey))

    if segwit_tx:
        for i in range(ins):
            wnum, tx = read_var_int(tx)
            witness = int_to_varint(wnum)
            for _ in range(wnum):
                w, tx = read_segwit_string(tx)
                witness += w
            inputs[i].witness = witness

    locktime, _ = read_bytes(tx, 4)

    txobj = TxObj(version, inputs, outputs, locktime)

    return txobj
