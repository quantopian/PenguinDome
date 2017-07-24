#!/usr/bin/env python3

import argparse
from base64 import b64decode
import os
import pprint
from pymongo import DESCENDING
import re
import subprocess
import sys
from tempfile import NamedTemporaryFile
import uuid

from qlmdm import (
    top_dir,
    var_dir,
    set_gpg,
    get_setting,
    set_setting,
    gpg_command,
    SelectorVariants,
)
import qlmdm.json as json
from qlmdm.server import (
    get_db,
    get_setting as get_server_setting,
    set_setting as set_server_setting,
    save_settings as save_server_settings,
    get_selectors,
    encrypt_document,
    get_logger,
)
from qlmdm.client import (
    set_setting as set_client_setting,
    save_settings as save_client_settings,
)

os.chdir(top_dir)
set_gpg('server')
log = get_logger('secret_keeping')

selectors_setting = 'secret_keeping:selectors'
restart_note = (
    "\nNOTE: Don't forget to build a new client release!\n")
distribute_secrets_note = '''
The {m} pieces of the secret-keeping key are in this directory:

{split_dir}

Please distribute these files securely to the secret-keepers and then remove
them with "shred -u". At least {n} of these files will need to be provided to
reconstruct the key so that secret data can be decrypted.
'''
audit_trail_selectors = (SelectorVariants('old', 'old', 'old', 'old'),
                         SelectorVariants('new', 'new', 'new', 'new'))


def parse_args():
    description = """QLMDM secret-keeping allows certain data submitted by
    clients to the server to be protected. The data are securely encrypted with
    a public key and can only be accessed if the corresponding private key is
    provided to the application. The data can then be protected from
    unauthorized, unaudited access by a single person, by using using "gfshare"
    or some other secret sharing mechanism to distribute pieces of the private
    key among multiple people and require more than one of them to provide
    their piece before it can be reassembled."""
    description = re.sub(r'\s\s+', ' ', description.strip())

    parser = argparse.ArgumentParser(description=description)

    subparsers = parser.add_subparsers()

    show_parser = subparsers.add_parser(
        'show', help='Show secret-keeping configuration')
    show_parser.set_defaults(func=show_handler)

    select_parser = subparsers.add_parser(
        'select', help='Add a database selector to the list of secret data')
    select_parser.add_argument(
        '--force', action='store_true',
        help="Add selectors even if they don't currently match anything")
    select_parser.add_argument(
        'selector', nargs='+', help='Selector(s) to add')
    select_parser.set_defaults(func=select_handler)

    deselect_parser = subparsers.add_parser(
        'deselect', help='Remove a database selector from the list of secret '
        'data')
    deselect_parser.add_argument(
        'selector', nargs='+', help='Selector(s) to remove')
    deselect_parser.set_defaults(func=deselect_handler)

    enable_parser = subparsers.add_parser(
        'enable', help='Enable secret-keeping')
    group = enable_parser.add_mutually_exclusive_group()
    group.add_argument(
        '--preserve', action='store_true', help="Preserve old encryption keys")
    group.add_argument(
        '--replace', action='store_true', help="Replace old encryption keys")
    enable_parser.add_argument('--shares', type=int, help='Number of pieces '
                               'to split the private key into')
    enable_parser.add_argument(
        '--combine-threshold', type=int,
        help='Number of pieces required to reconstruct the private key')
    enable_parser.set_defaults(func=enable_handler)

    disable_parser = subparsers.add_parser(
        'disable', help='Disable secret-keeping')
    disable_parser.set_defaults(func=disable_handler)

    encrypt_parser = subparsers.add_parser(
        'encrypt', help='Persistently encrypt secret data in the database')
    encrypt_parser.set_defaults(func=encrypt_handler)

    decrypt_parser = subparsers.add_parser(
        'decrypt', help='Persistently decrypt encrypted data in the database')
    decrypt_parser.set_defaults(func=decrypt_handler)

    access_parser = subparsers.add_parser(
        'access', help='Decrypt secret data in memory and display it')
    access_parser.add_argument('--hostname', action='append',
                               help='Host name(s) to display data for')
    access_parser.add_argument('--full', action='store_true', help='Display '
                               'full documents, not just decrypted fields')
    access_parser.add_argument('--audit-trail', action='store_true',
                               help='Also display audit trail')
    access_parser.set_defaults(func=access_handler)

    args = parser.parse_args()
    return args


def show_handler(args):
    config = get_server_setting('secret_keeping') or {}
    config['enabled'] = get_server_setting('secret_keeping:enabled')
    pprint.pprint(config)


def select_handler(args):
    selectors = get_server_setting(selectors_setting)
    if isinstance(selectors, str):
        selectors = [selectors]
        set_server_setting(selectors_setting, selectors)
    if selectors is None:
        selectors = []
        set_server_setting(selectors_setting, selectors)

    errors = False
    for selector in args.selector:
        if selector in selectors:
            sys.stderr.write('Selector {} is already added.\n'.format(
                selector))
            errors = True
    if errors:
        sys.exit(1)

    if not args.force:
        db = get_db()
        for selector in args.selector:
            if not db.clients.find_one({selector: {'$exists': True}},
                                       projection=[]):
                sys.stderr.write('Selector {} does not match anything.\n'
                                 'Specify --force to save anyway.\n'.
                                 format(selector))
                errors = True
        if errors:
            sys.exit(1)

    for selector in args.selector:
        log.info('Adding secret-keeping selector {}', selector)

    selectors.extend(args.selector)
    save_server_settings()

    set_client_setting(selectors_setting, selectors)
    save_client_settings()

    print(restart_note)


def deselect_handler(args):
    selectors = get_server_setting(selectors_setting)
    if isinstance(selectors, str):
        selectors = [selectors]
        set_server_setting(selectors_setting, selectors)
    if selectors is None:
        selectors = []
        set_server_setting(selectors_setting, selectors)

    errors = False
    for selector in args.selector:
        try:
            selectors.remove(selector)
        except ValueError:
            sys.stderr.write('Selector {} is not currently selected.\n'.format(
                selector))
            errors = True
    if errors:
        sys.exit(1)

    for selector in args.selector:
        log.info('Removing secret-keeping selector {}', selector)

    save_server_settings()

    set_client_setting(selectors_setting, selectors)
    save_client_settings()

    print(restart_note)


def enable_handler(args):
    if get_server_setting('secret_keeping:enabled'):
        sys.exit('Secret-keeping is already enabled.')

    if get_server_setting('secret_keeping:key_id'):
        if not (args.replace or args.preserve):
            sys.exit('Must specify --replace or --preserve.')
    else:
        args.replace = True

    args.shares = args.shares or \
        get_server_setting('secret_keeping:num_shares')
    if args.shares < 2:
        sys.exit('--num-shares must be at least 2.')

    args.combine_threshold = args.combine_threshold or \
        get_server_setting('secret_keeping:combine_threshold')
    if args.combine_threshold < 2:
        sys.exit('--combine-threshold must be at least 2.')
    if args.combine_threshold > args.shares:
        sys.exit('--combine-threshold must be less than {}.'.format(
            args.shares + 1))

    if args.replace:
        key_name = 'qlmdm-secret-keeping-' + uuid.uuid4().hex
        output = gpg_command('--passphrase', '', '--quick-gen-key', key_name,
                             with_trustdb=True, quiet=False)
        match = re.search(r'key (.*) marked as ultimately trusted', output)
        key_id = match.group(1)
        match = re.search(r'/([0-9A-F]+)\.rev', output)
        key_fingerprint = match.group(1)

        split_dir = os.path.join(var_dir, key_name)
        key_file = os.path.join(split_dir, 'private_key.asc')
        os.makedirs(split_dir)
        gpg_command('--export-secret-key', '--armor', '-o', key_file, key_id)
        subprocess.check_output(('gfsplit', '-n', str(args.combine_threshold),
                                 '-m', str(args.shares), key_file),
                                stderr=subprocess.STDOUT)
        try:
            gpg_command('--delete-secret-keys', key_fingerprint)
        except subprocess.CalledProcessError as e:
            sys.exit('Failed to delete secret key:\n{}'.format(
                e.output.decode('ascii')))
        subprocess.check_output(('shred', '-u', key_file),
                                stderr=subprocess.STDOUT)

        with NamedTemporaryFile() as public_key_file:
            gpg_command('--export', '-o', public_key_file.name, key_id)
            set_gpg('client')
            try:
                gpg_command('--import', public_key_file.name)
            finally:
                set_gpg('server')

        set_server_setting('secret_keeping:key_name', key_name)
        set_server_setting('secret_keeping:key_id', key_id)
        set_server_setting('secret_keeping:key_fingerprint', key_fingerprint)

        set_client_setting('secret_keeping:key_id', key_id)

    set_server_setting('secret_keeping:num_shares', args.shares)
    set_server_setting('secret_keeping:combine_threshold',
                       args.combine_threshold)
    set_server_setting('secret_keeping:enabled', True)
    save_server_settings()

    set_client_setting('secret_keeping:enabled', True)
    save_client_settings()

    print(distribute_secrets_note.format(
        m=args.shares, n=args.combine_threshold, split_dir=split_dir))
    print(restart_note)

    log.info('Enabled secret-keeping')


def disable_handler(args):
    if not get_server_setting('secret_keeping:enabled'):
        sys.exit('Secret-keeping is not enabled.')

    set_server_setting('secret_keeping:enabled', False)
    save_server_settings()

    set_client_setting('secret_keeping:enabled', False)
    save_client_settings()

    print(restart_note)

    log.info('Disabled secret-keeping')


def encrypt_handler(args):
    if not get_server_setting('secret_keeping:enabled'):
        sys.exit('You cannot encrypt when secret-keeping is disabled.')
    db = get_db()
    selectors = get_selectors()
    spec = {'$or': [{s.plain_mongo: {'$exists': True}} for s in selectors]}
    for doc in db.clients.find(spec):
        doc, update = encrypt_document(doc)
        if update:
            db.clients.update({'_id': doc['_id']}, update)
            log.info('Encrypted data in client document {} (host {})',
                     doc['_id'], doc['hostname'])
            print('Encrypted client document {} (host {})'.format(
                doc['_id'], doc['hostname']))
    spec = {'key': {'$in': [s.plain_mongo for s in selectors]}}
    for doc in db.audit_trail.find(spec):
        doc, update = encrypt_document(doc, selectors=audit_trail_selectors)
        if update:
            update['$set']['key'] = next(s.enc_mongo for s in selectors if
                                         s.plain_mongo == doc['key'])
            db.audit_trail.update({'_id': doc['_id']}, update)
            log.info('Encrypted data in audit trail document {} (host {})',
                     doc['_id'], doc['hostname'])
            print('Encrypted audit trail document {} (host {})'.format(
                doc['_id'], doc['hostname']))


def combine_secret_key():
    key_name = get_server_setting('secret_keeping:key_name')
    split_dir = os.path.join(var_dir, key_name)
    key_file = os.path.join(split_dir, 'private_key.asc')
    os.makedirs(split_dir, exist_ok=True)
    split_files = [f for f in os.listdir(split_dir) if re.search(r'\.\d', f)]
    combine_threshold = get_server_setting('secret_keeping:combine_threshold')
    if len(split_files) < combine_threshold:
        input('Put at least {} of the secret-keeper files into\n{}.\n'
              'Hit Enter when done: '.format(combine_threshold, split_dir))
        split_files = [f for f in os.listdir(split_dir)
                       if re.search(r'\.\d', f)]
        if len(split_files) < combine_threshold:
            sys.exit('Too few secret-keeper files provided.')
    cmd = ['gfcombine', '-o', key_file]
    cmd.extend(os.path.join(split_dir, f) for f in split_files)
    subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    gpg_command('--import', key_file)
    subprocess.check_output(('shred', '-u', key_file))


def delete_secret_key():
    key_fingerprint = get_server_setting('secret_keeping:key_fingerprint')
    gpg_command('--delete-secret-keys', key_fingerprint)
    print("\nDon't forget to 'shred -u' the secret-keeper files!\n")
    log.warn("Don't forget to 'shred -u' the secret-keeper files!")


def decrypt_iterator(document_iterator, document_keys=None, selectors=None,
                     full_documents=False):
    """Decrypt documents and return decrypted data

    `selectors` defaults to `get_selectors()`

    Each yield is a tuple of a document containing the document keys, a
    document containing the decrypted data in the same structure as the
    original document, and a list of tuples of selectors that were decrypted
    and the decrypted datum for each selector. I.e., the same decrypted data is
    returned in two different forms, to simplify the use of the data by the
    caller.

    if `full_documents` is true, then the document in each yield will be the
    full document returned by the iterator with encrypted fields replaced,
    rather than a document containing just the decrypted fields.

    Assumes that the secret key has already been combined _before_ this
    function is called.

    Note: There is a yield for every document that is returned by
    document_iterator, even if nothing was decrypted. If that's the case, then
    the document keys in the yield will be populated, but the decrypted data
    document and list will be empty.
    """
    if selectors is None:
        selectors = get_selectors()
    for doc in document_iterator:
        document_keys = {k: doc[k] for k in document_keys or ()}
        output_dict = doc if full_documents else {}
        output_tuples = []
        for s in selectors:
            encrypted_data = get_setting(doc, s.enc_mem,
                                         check_defaults=False)
            if not encrypted_data:
                continue
            with NamedTemporaryFile('w+b') as unencrypted_file, \
                    NamedTemporaryFile('w+b') as encrypted_file:
                encrypted_file.write(b64decode(encrypted_data['data']))
                encrypted_file.flush()
                gpg_command('--decrypt', '-o', unencrypted_file.name,
                            encrypted_file.name)
                unencrypted_file.seek(0)
                unencrypted_data = json.loads(
                    unencrypted_file.read().decode('utf-8'))
            # Order is important here. We unset before we set because the
            # selector key may be the same for both unencrypted and encrypted
            # fields.
            if full_documents:
                set_setting(output_dict, s.enc_mem, None)
            set_setting(output_dict, s.plain_mem, unencrypted_data)
            output_tuples.append((s, unencrypted_data))
        yield (document_keys, output_dict if output_tuples else {},
               output_tuples)


def decrypt_handler(args):
    combine_secret_key()
    selectors = get_selectors()
    try:
        db = get_db()
        spec = {'$or': [{s.enc_mongo: {'$exists': True}} for s in selectors]}
        for keys, dct, tuples in decrypt_iterator(db.clients.find(spec),
                                                  ('_id', 'hostname'),
                                                  selectors=selectors):
            if dct:
                spec = {'_id': keys['_id']}
                update = {'$set': {s.plain_mongo: u for s, u in tuples},
                          '$unset': {s.enc_mongo: True for s, u in tuples}}
                db.clients.update(spec, update)
                log.info('Decrypted data in client document {} (host {})',
                         keys['_id'], keys['hostname'])
                print('Decrypted client document {} (host {})'.format(
                    keys['_id'], keys['hostname']))

        spec = {'key': {'$in': [s.enc_mongo for s in selectors]}}
        for keys, dct, tuples in decrypt_iterator(
                db.audit_trail.find(spec), selectors=audit_trail_selectors,
                full_documents=True):
            if dct:
                dct['key'] = next(s.plain_mongo for s in selectors if
                                  s.enc_mongo == dct['key'])
                spec = {'_id': dct['_id']}
                db.audit_trail.update(spec, dct)
                log.info('Decrypted data in audit trail document {} (host {})',
                         dct['_id'], dct['hostname'])
                print('Decrypted audit trail document {} (host {})'.format(
                    dct['_id'], dct['hostname']))
    finally:
        delete_secret_key()


def access_handler(args):
    combine_secret_key()
    selectors = get_selectors()
    try:
        db = get_db()
        spec = {'$or': [{s.enc_mongo: {'$exists': True}} for s in selectors]}
        printed_header = not args.audit_trail
        for keys, dct, tuples in decrypt_iterator(
                db.clients.find(spec), ('_id', 'hostname'),
                full_documents=args.full, selectors=selectors):
            if dct:
                if not printed_header:
                    print('Clients:\n')
                    printed_header = True
                pprint.pprint({**keys, **dct})
                log.info('Displayed encrypted data in document {} (host {})',
                         keys['_id'], keys['hostname'])
        if args.audit_trail:
            if printed_header:
                print('')
            spec = {'key': {'$in': [s.enc_mongo for s in selectors]}}
            printed_header = False
            for keys, dct, tuples in decrypt_iterator(
                    db.audit_trail.find(spec, sort=(('_id', DESCENDING),)),
                    selectors=audit_trail_selectors, full_documents=True):
                if dct:
                    if not printed_header:
                        print('Audit trail:\n')
                        printed_header = True
                    dct['key'] = next(s.plain_mongo for s in selectors if
                                      s.enc_mongo == dct['key'])
                    pprint.pprint(dct)
                    log.info('Displayed encrypted audit trail in document {} '
                             '(host {})', dct['_id'], dct['hostname'])
    finally:
        delete_secret_key()


def main():
    args = parse_args()

    args.func(args)


if __name__ == '__main__':
    main()
