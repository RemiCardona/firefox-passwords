#!/usr/bin/env python
"Recovers your Firefox or Thunderbird passwords"

import base64
import json
from collections import namedtuple
from ConfigParser import RawConfigParser
from ctypes import (Structure, CDLL, byref, cast, string_at, c_void_p,
    c_uint, c_ubyte, c_char_p)
from getpass import getpass
import logging
from optparse import OptionParser
import os
import sys


LOGLEVEL_DEFAULT = 'warn'

log = logging.getLogger()
PWDECRYPT = 'pwdecrypt'

SITEFIELDS = ['id', 'hostname', 'httpRealm', 'formSubmitURL', 'usernameField',
'passwordField', 'encryptedUsername', 'encryptedPassword', 'guid', 'encType',
'plain_username', 'plain_password',
'timePasswordChanged', 'timeCreated',
'timesUsed', 'timeLastUsed']
Site = namedtuple('FirefoxSite', SITEFIELDS)


#### These are libnss definitions ####
class SECItem(Structure):
    _fields_ = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]

class secuPWData(Structure):
    _fields_ = [('source', c_ubyte), ('data', c_char_p)]

(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0, 1, 2, 3)
# SECStatus
(SECWouldBlock, SECFailure, SECSuccess) = (-2, -1, 0)
#### End of libnss definitions ####


def get_default_firefox_profile_directory(profiles_dir):
    '''Returns the directory name of the default profile

    If you changed the default dir to something like ~/.thunderbird,
    you would get the Thunderbird default profile directory.'''

    profile_path = None

    cp = RawConfigParser()
    cp.read(os.path.join(profiles_dir, "profiles.ini"))
    for section in cp.sections():
        if not cp.has_option(section, "Path"):
            continue

        if (not profile_path or
            (cp.has_option(section, "Default") and cp.get(section, "Default").strip() == "1")):
            profile_path = os.path.join(profiles_dir, cp.get(section, "Path").strip())

    if not profile_path:
        raise RuntimeError("Cannot find default Firefox profile")

    return profile_path


def get_encrypted_sites(firefox_profile_dir):
    'Opens logins.json and yields encryped password data'

    logins_json = os.path.join(firefox_profile_dir, "logins.json")
    with open(logins_json) as fobj:
        logins_data = json.load(fobj)

    for login_dict in logins_data['logins']:
        login_dict = {key: login_dict.get(key) for key in login_dict}
        login_dict.update(plain_username=None, plain_password=None)
        yield Site(**login_dict)


class NativeDecryptor(object):
    'Calls the NSS API to decrypt strings'

    def __init__(self, directory, password=''):
        '''You need to give the profile directory and optionally a
        password. If you don't give a password but one is needed, you
        will be prompted by getpass to provide one.'''
        self.directory = directory
        self.log = logging.getLogger('NativeDecryptor')
        self.log.debug('Trying to work on %s', directory)

        self.libnss = CDLL('libnss3.so')
        if self.libnss.NSS_Init(directory) != 0:
            self.log.error('Could not initialize NSS')

        # Initialize to the empty string, not None, because the password
        # function expects rather an empty string
        password = password or ''

        slot = self.libnss.PK11_GetInternalKeySlot()

        pw_good = self.libnss.PK11_CheckUserPassword(slot, c_char_p(password))
        while pw_good != SECSuccess:
            msg = 'Password is not good (%d)!' % pw_good
            print >>sys.stderr, msg
            password = getpass('Please enter password: ')
            pw_good = self.libnss.PK11_CheckUserPassword(slot, c_char_p(password))

    def __del__(self):
        self.libnss.NSS_Shutdown()

    def decrypt(self, string):
        'Decrypts a given string'

        libnss = self.libnss

        dectext = SECItem()

        cstring = SECItem()
        cstring.data = cast(c_char_p(base64.b64decode(string)), c_void_p)
        cstring.len = len(base64.b64decode(string))
        self.log.debug('Trying to decrypt %s (error: %s)', string, libnss.PORT_GetError())
        if libnss.PK11SDR_Decrypt(byref(cstring), byref(dectext)) == -1:
            error = libnss.PORT_GetError()
            libnss.PR_ErrorToString.restype = c_char_p
            error_str = libnss.PR_ErrorToString(error)
            raise Exception("%d: %s" % (error, error_str))

        decrypted_data = string_at(dectext.data, dectext.len)

        return decrypted_data

    def encrypted_sites(self):
        'Yields the encryped passwords from the profile'
        sites = get_encrypted_sites(self.directory)

        return sites

    def decrypted_sites(self):
        'Decrypts the encrypted_sites and yields the results'

        sites = self.encrypted_sites()

        for site in sites:
            plain_user = self.decrypt(site.encryptedUsername)
            plain_password = self.decrypt(site.encryptedPassword)
            site = site._replace(plain_username=plain_user,
                plain_password=plain_password)

            yield site


def main_decryptor(profile_directory, password, thunderbird=False):
    'Main function to get Firefox and Thunderbird passwords'
    if not profile_directory:
        if thunderbird:
            default_profiles_dir = os.path.expanduser('~/.thunderbird/')
        else:
            default_profiles_dir = os.path.expanduser('~/.mozilla/firefox')
        profile_directory = get_default_firefox_profile_directory(default_profiles_dir)
    else:
        profile_directory = os.path.expanduser(profile_directory)

    decryptor = NativeDecryptor(profile_directory, password)

    for site in decryptor.decrypted_sites():
        print site


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-d", "--directory", default=None,
                  help="the Firefox profile directory to use")
    parser.add_option("-p", "--password", default=None,
                  help="the master password for the Firefox profile")
    parser.add_option("-l", "--loglevel", default=LOGLEVEL_DEFAULT,
                  help="the level of logging detail [debug, info, warn, critical, error]")
    parser.add_option("-t", "--thunderbird", default=False, action='store_true',
                  help="by default we try to find the Firefox default profile."
                  " But you can as well ask for Thunderbird's default profile."
                  " For a more reliable way, give the directory with -d.")
    options, args = parser.parse_args()

    loglevel = {'debug': logging.DEBUG, 'info': logging.INFO,
                'warn': logging.WARN, 'critical':logging.CRITICAL,
                'error': logging.ERROR}.get(options.loglevel, LOGLEVEL_DEFAULT)
    logging.basicConfig(level=loglevel)
    log = logging.getLogger()

    password = options.password

    sys.exit(main_decryptor(options.directory, password, thunderbird=options.thunderbird))
