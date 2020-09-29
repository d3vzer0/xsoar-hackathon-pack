import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_records(requests_mock):
    from CertificateTransparency import Client, get_records_command
    mock_records = util_load_json('test_data/get_records_response.json')
    requests_mock.get('https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=5&end=6',
                      json=mock_records)
    client = Client(
        base_url='https://ct.googleapis.com/logs/argon2020/',
        verify=False,
        proxy=False)

    args = {'Start': 5, 'End': 6, 'Url': 'https://ct.googleapis.com/logs/argon2020/'}
    response = get_records_command(client, args)
    assert response.outputs == util_load_json('test_data/get_records_result.json')
    assert response.outputs_prefix == 'CertificateTransparency.Cert'
    assert response.outputs_key_field == 'Fingerprint'


def test_get_operators(requests_mock):
    from CertificateTransparency import Client, get_operators_command
    mock_operators = util_load_json('test_data/get_operators_response.json')
    requests_mock.get('https://www.examplect.com/ct/log_list/v2/log_list.json',
                      json=mock_operators)
    client = Client(
        base_url='https://www.examplect.com/ct/log_list/v2/',
        verify=False,
        proxy=False)

    args = {'File': 'log_list.json', 'Url': 'https://www.examplect.com/ct/log_list/v2/'}
    response = get_operators_command(client, args)
    assert response.outputs == util_load_json('test_data/get_operators_results.json')
    assert response.outputs_prefix == 'CertificateTransparency.Operator'
    assert response.outputs_key_field == 'Url'


def test_tree_size(requests_mock):
    from CertificateTransparency import Client, get_tree_size_command
    mock_tree = util_load_json('test_data/get_tree_size_response.json')
    requests_mock.get('https://ct.exampleop.com/logs/2020/ct/v1/get-sth',
                      json=mock_tree)
    client = Client(
        base_url='https://ct.exampleop.com/logs/2020/',
        verify=False,
        proxy=False)

    args = {'Url': 'https://ct.exampleop.com/logs/2020/'}
    response = get_tree_size_command(client, args)
    assert response.outputs == util_load_json('test_data/get_tree_size_results.json')
    assert response.outputs_prefix == 'CertificateTransparency.Tree'
    assert response.outputs_key_field == 'Url'
