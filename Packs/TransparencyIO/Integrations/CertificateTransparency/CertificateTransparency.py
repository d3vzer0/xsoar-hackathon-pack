import demistomock as demisto
from urllib.parse import urlparse
from CommonServerPython import *
from CommonServerUserPython import *
from OpenSSL import crypto
from construct import (Struct, Byte, Int16ub, Int64ub, Enum,
                       Bytes, Int24ub, this, GreedyBytes, GreedyRange, Terminated,
                       Embedded)
import base64
import redis
import requests
import json
import hashlib
import re
requests.packages.urllib3.disable_warnings()

# Name of the integration
INTEGRATION_NAME = 'CertificateTransparency'

# Structure of transparency tree containing the certificates
MERKLETREEHEADER = Struct(
    "Version" / Byte,
    "MerkleLeafType" / Byte,
    "Timestamp" / Int64ub,
    "LogEntryType" / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry" / GreedyBytes
)

CERTIFICATE = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

CERTIFICATECHAIN = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(CERTIFICATE),
)

PRECERTENTRY = Struct(
    "LeafCert" / CERTIFICATE,
    Embedded(CERTIFICATECHAIN),
    Terminated
)


# Class to decode certificate into readable dict
class Certificate:
    def __init__(self, certificate):
        self.certificate = certificate

    def details(self):
        issuer = self.certificate.get_issuer()
        subject = self.certificate.get_subject()
        decoded_certificate = {
            'issuer': {
                component[0].decode('utf-8'): component[1].decode('utf-8')
                for component in issuer.get_components()},
            'not_after': self.certificate.get_notAfter().decode('utf-8'),
            'not_before': self.certificate.get_notBefore().decode('utf-8'),
            'serial': str(self.certificate.get_serial_number()),
            'algorithm': self.certificate.get_signature_algorithm().decode('utf-8'),
            'version': self.certificate.get_version(),
            'subject': {
                component[0].decode('utf-8'): component[1].decode('utf-8')
                for component in subject.get_components()},
            'fingerprint': self.certificate.digest("sha1").decode('utf-8')}

        return decoded_certificate


# Class to traverse the transparency tree, returns certificate details in
# dictionary format
class MerkleTree(Certificate):
    def __init__(self, entry):
        leaf_input = base64.b64decode(entry['leaf_input'])
        self.leaf_data = MERKLETREEHEADER.parse(leaf_input)
        self.extra_data = base64.b64decode(entry['extra_data'])

    def precert(self):
        data_object = PRECERTENTRY.parse(self.extra_data)
        entry = Certificate(crypto.load_certificate(crypto.FILETYPE_ASN1, data_object.LeafCert.CertData)).details()
        chain = [
            Certificate(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)).details()
            for cert in data_object.Chain]
        result = {'type': 'precert', **entry, 'chain': chain}
        return result

    def log(self):
        extra_data = CERTIFICATECHAIN.parse(self.extra_data)
        entry = Certificate(
            crypto.load_certificate(crypto.FILETYPE_ASN1, CERTIFICATE.parse(self.leaf_data.Entry).CertData)).details()
        chain = [
            Certificate(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)).details()
            for cert in extra_data.Chain]
        result = {'type': 'log', **entry, 'chain': chain}
        return result

    def parse(self):
        parse_functions = {
            'X509LogEntryType': self.log,
            'PrecertLogEntryType': self.precert}
        decode_tree = parse_functions[self.leaf_data.LogEntryType]()
        return decode_tree


class Client(BaseClient):
    def get_operators(self, operators_file: str):
        return self._http_request(
            url_suffix=operators_file,
            method='GET')

    def get_tree_size(self):
        return self._http_request(
            method='GET',
            url_suffix='/ct/v1/get-sth')

    def get_records(self, start: str, end: str):
        return self._http_request(
            method='GET',
            url_suffix=f'/ct/v1/get-entries?start={start}&end={end}'
        )


class Cache:
    def __init__(self, host, password, db=0, port=6379):
        self.session = redis.Redis(host=host, port=port, db=db, password=password)

    def set(self, data, ttl=None, key=None):
        key = key if key else hashlib.sha224(str(data).encode('utf-8')).hexdigest()
        self.session.set(key, data, ex=ttl)
        return key

    def get(self, key):
        return self.session.get(key)


def match_regex_command(cache, args=None):
    demisto.info('Matching CT records with regular expression(s)')
    decoded_records = json.loads(cache.get(args['Key']))
    regex_list = argToList(args['RegexList'])
    matched_records = []
    for record in decoded_records:
        common_name = record['Subject'].get('CN')
        if common_name:
            combined_regex = f'(?:{"|".join(regex_list)})'
            match_record = re.match(combined_regex, common_name)
            if match_record:
                matched_records.append({**record, 'regex': combined_regex})

    results = CommandResults(
        outputs_prefix='CertificateTransparency.Cert',
        outputs_key_field='Fingerprint',
        outputs=matched_records,
        readable_output=tableToMarkdown(
            'Matched recods',
            { match['Subject']['CN']: match['regex'] for match in matched_records}
        )
    )
    return results


def get_records_command(client, cache, args=None):
    demisto.info('Downloading certificates from operator log')
    range_end = int(args['End']) - 1
    range_start = int(args['Start'])
    max_lag = int(args.get('MaxLag', 300))
    if (range_end - range_start) > max_lag:
        range_start = range_end - max_lag

    decoded_records = []
    while (range_end - range_start) >= 0:
        demisto.info(f'Downloading certificates range {range_start} - {range_end} from {args["Url"]}')
        get_records = client.get_records(range_start, range_end)['entries']
        for record in get_records:
            decoded_record = MerkleTree(record).parse()
            decoded_records.append({
                'Subject': {
                    'C': decoded_record['subject'].get('C'),
                    'ST': decoded_record['subject'].get('ST'),
                    'O': decoded_record['subject'].get('O'),
                    'OU': decoded_record['subject'].get('OU'),
                    'CN': decoded_record['subject'].get('CN')
                },
                'NotAfter': decoded_record['not_after'],
                'NotBefore': decoded_record['not_before'],
                'Serial': decoded_record['serial'],
                'Fingerprint': decoded_record['fingerprint'],
                'Issuer': {
                    'C': decoded_record['issuer'].get('C'),
                    'ST': decoded_record['issuer'].get('ST'),
                    'O': decoded_record['issuer'].get('O'),
                    'OU': decoded_record['issuer'].get('OU'),
                    'CN': decoded_record['issuer'].get('CN'),
                    'SerialNumber': decoded_record['issuer'].get('serialNumber')
                }
            })

        range_start += len(get_records)
        cache.set(range_start, key=args['Url'])

    cache_records = cache.set(json.dumps(decoded_records), ttl=600)
    output = {'Key': cache_records, 'Url': args['Url'], 'Count': len(decoded_records)}
    results = CommandResults(
        outputs_prefix='CertificateTransparency.Cache',
        outputs_key_field='Key',
        outputs={'Key': cache_records, 'Url': args['Url'], 'Count': len(decoded_records)},
        readable_output=tableToMarkdown(
            'Fetched records from CT operator log',
            output
        )
    )
    return results


def get_tree_size_command(client, args=None):
    demisto.info('Downloading tree size for operator')
    get_tree_size = client.get_tree_size()
    operator_tree_data = {
        'Url': args['Url'],
        'Size': get_tree_size['tree_size'],
        'Date': get_tree_size['timestamp'],
        'RootHash': get_tree_size['sha256_root_hash']
    }

    results = CommandResults(
        outputs_prefix='CertificateTransparency.Tree',
        outputs_key_field='Url',
        outputs=operator_tree_data,
        raw_response=get_tree_size,
        readable_output=tableToMarkdown(
            'Fetched tree size for CT operator',
            operator_tree_data
        )
    )
    return results


def get_operators_command(client, args=None):
    demisto.info('Downloading list of transparency operators')
    all_operators = []
    get_operators = client.get_operators(args['File'])
    for operator in get_operators['operators']:
        for log in operator['logs']:
            all_operators.append({
                'Name': operator['name'],
                'Url': log['url'],
                'Description': log['description']}
            )

    results = CommandResults(
        outputs_prefix='CertificateTransparency.Operator',
        outputs_key_field='Url',
        outputs=all_operators,
        raw_response=get_operators,
        readable_output=tableToMarkdown(
            'Fetched list of transparency operators',
            {op['name']: len(op['logs']) for op in get_operators['operators']}
        )
    )
    return results


def main():
    proxy = demisto.params().get('proxy', False)
    verify_certificate = demisto.params().get('insecure', False)
    blocklist = demisto.params().get('blocklist', [])
    redis_host = demisto.params().get('redis_host')
    redis_password = demisto.params().get('redis_password')
    redis_db = int(demisto.params().get('redis_db', 0))
    redis_port = int(demisto.params().get('redis_port', 6379))

    client = Client(
        verify=verify_certificate,
        proxy=proxy,
        base_url=demisto.args().get('Url', None)
    )

    cache = Cache(
        redis_host,
        redis_password,
        db=redis_db,
        port=redis_port
    )

    try:
        if demisto.command() == 'get-operators':
            return_results(get_operators_command(
                client, demisto.args()))

        if demisto.command() == 'get-tree-size':
            operator_host = urlparse(demisto.args()['Url'])
            if operator_host.netloc not in blocklist.splitlines():
                return_results(get_tree_size_command(
                    client, demisto.args()))

        if demisto.command() == 'get-records':
            args = demisto.args()
            if not cache.get(args['Url']):
                cache.set(int(args['End']) - int(args.get('MaxLag', 300)), key=args['Url'])
            args['Start'] = args.get('Start', cache.get(args['Url']))
            return_results(get_records_command(
                client, cache, args))

        if demisto.command() == 'ct-match-regex':
            # regex_list = demisto.executeCommand("getList", {"listName": 'ja'})
            return_results(match_regex_command(
                cache, demisto.args()))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
