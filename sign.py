# Koji callback for GPG signing RPMs before import
# Consider sigul for a more robust solution -- https://fedorahosted.org/sigul/
#
# Author:
#     Paul B Schroeder <paulbsch "at" vbridges "dot" com>

from koji.plugin import register_callback
from tempfile import TemporaryFile
import logging
import os
import pexpect
import re

# Get the tag name from the buildroot map
import sys
sys.path.insert(0, '/usr/share/koji-hub')
from kojihub import get_buildroot

# Configuration file in /etc like for other plugins
config_file = '/etc/koji-hub/plugins/sign.conf'

GPG_EXPECTS = ['Enter passphrase:', pexpect.EOF, 'failed', 'skipping', 'error', pexpect.TIMEOUT]
ERROR_MESSAGES = {
    2: 'Package signing failed!',
    3: 'Package signing skipped!',
    4: 'Package signing error!',
    5: 'Package signing timed out!'
}

def sign(cbtype, *args, **kws):
    if kws['type'] != 'build':
       return

    br_id = list(kws['brmap'].values())[0]
    br = get_buildroot(br_id)
    tag_name = br['tag_name']

    logging.getLogger('koji.plugin.sign').info("Got package with tag_name %s", tag_name)

    # Get GPG info using the config for the tag name
    try:
        from ConfigParser import ConfigParser, NoOptionError
    except ImportError:  # Python 3
        from configparser import ConfigParser, NoOptionError
    config = ConfigParser()
    config.read(config_file)
    if not config.has_section(tag_name):
       tag_name = "DEFAULT"
    rpm = config.get(tag_name, 'rpm')
    gpgbin = config.get(tag_name, 'gpgbin')
    gpg_path = config.get(tag_name, 'gpg_path')
    gpg_name = config.get(tag_name, 'gpg_name')
    gpg_pass = config.get(tag_name, 'gpg_pass')
    try:
        gpg_digest_algo = config.get(tag_name, 'gpg_digest_algo')
    except NoOptionError:
        gpg_digest_algo = None
    try:
        enabled = config.getboolean(tag_name, 'enabled')
    except NoOptionError:
        # Note that signing is _enabled_ by default
        enabled = True

    
    if not enabled:
        logging.getLogger('koji.plugin.sign').info('Signing not enabled for this tag.')
        return

    # Get the package paths set up
    from koji import pathinfo
    uploadpath = pathinfo.work()
    rpm_paths = [f'{uploadpath}/{relpath}' for relpath in [kws['srpm']] + kws['rpms']]
    rpms = ' '.join(rpm_paths)

    # Get the packages signed
    os.environ['LC_ALL'] = 'C'
    logging.getLogger('koji.plugin.sign').info('Attempting to sign packages'
       ' (%s) with key "%s"' % (rpms, gpg_name))
    rpm_cmd = "%s --resign --define '_signature gpg'" % rpm
    rpm_cmd += " --define '_gpgbin %s'" % gpgbin
    rpm_cmd += " --define '_gpg_path %s'" % gpg_path
    if gpg_digest_algo:
        rpm_cmd += " --define '_gpg_digest_algo %s'" % gpg_digest_algo
    rpm_cmd += " --define '_gpg_name %s' %s" % (gpg_name, rpms)
    pex = pexpect.spawn(rpm_cmd, timeout=30)
    # Add rpm output to a temporary file
    fout = TemporaryFile()
    pex.logfile = fout

    result = 0
    # Yubikey occassionally requests password twice, I have no idea why
    while result == 0:
        # With pinentry-mode loopback, this is the only prompt output by GPG
        result = pex.expect(GPG_EXPECTS, timeout=30)
        if result == 0:
            pex.sendline(gpg_pass)

    pex.close()
    ok = True
    if result < 2:
        logging.getLogger('koji.plugin.sign').info('Package sign successful!')
    else:
        logging.getLogger('koji.plugin.sign').error(ERROR_MESSAGES.get(result, "Unknown signing error!"))
        ok = False
    if not ok:
        fout.seek(0)
        # Add GPG errors to log
        errors = ''
        for line in fout.readlines():
            errors += line.decode().replace(gpg_pass, '<gpg pass>')
        fout.close()
        raise Exception('Package sign failed!\n' + errors)
    else:
        fout.close()


    # Sanity check, ensure that a signature exists for each rpm
    non_signed_rpms = []
    for processed_rpm in rpm_paths:
        rpm_cmd = f"{rpm} -qpi {processed_rpm}"
        pex = pexpect.spawn(rpm_cmd, timeout=1000)
        result = pex.expect(['Signature.*:.*Key ID.*',pexpect.EOF], timeout=5)
        pex.close()
        if result != 0:
            non_signed_rpms.append(processed_rpm)

    if len(non_signed_rpms) > 0:
        raise Exception('Signatures missing from the following packages: ' + ' '.join(non_signed_rpms))



register_callback('preImport', sign)
