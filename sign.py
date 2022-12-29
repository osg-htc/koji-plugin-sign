# Koji callback for GPG signing RPMs before import
# Consider sigul for a more robust solution -- https://fedorahosted.org/sigul/
#
# Author:
#     Paul B Schroeder <paulbsch "at" vbridges "dot" com>

from koji.plugin import register_callback
import logging

# Configuration file in /etc like for other plugins
config_file = '/etc/koji-hub/plugins/sign.conf'

def sign(cbtype, *args, **kws):
    if kws['type'] != 'build':
       return

    # Get the tag name from the buildroot map
    import sys
    sys.path.insert(0, '/usr/share/koji-hub')
    from kojihub import get_buildroot
    br_id = kws['brmap'].values()[0]
    br = get_buildroot(br_id)
    tag_name = br['tag_name']

    logging.getLogger('koji.plugin.sign').info("Got package with tag_name %s", tag_name)

    # Get GPG info using the config for the tag name
    from ConfigParser import ConfigParser, NoOptionError
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
    rpms = ''
    for relpath in [kws['srpm']] + kws['rpms']:
       rpms += '%s/%s ' % (uploadpath, relpath)

    # Get the packages signed
    import pexpect
    import os
    os.environ['LC_ALL'] = 'C'
    logging.getLogger('koji.plugin.sign').info('Attempting to sign packages'
       ' (%s) with key "%s"' % (rpms, gpg_name))
    rpm_cmd = "%s --resign --define '_signature gpg'" % rpm
    rpm_cmd += " --define '_gpgbin %s'" % gpgbin
    rpm_cmd += " --define '_gpg_path %s'" % gpg_path
    if gpg_digest_algo:
        rpm_cmd += " --define '_gpg_digest_algo %s'" % gpg_digest_algo
    rpm_cmd += " --define '_gpg_name %s' %s" % (gpg_name, rpms)
    pex = pexpect.spawn(rpm_cmd, timeout=1000)
    # Add rpm output to a temporary file
    fout = os.tmpfile()
    pex.logfile = fout
    pex.expect('(E|e)nter (P|p)ass (P|p)hrase:', timeout=1000)
    if not gpg_pass:
        pex.sendline('\r')
    else:
        pex.sendline(gpg_pass)
    i = pex.expect(['good', 'failed', 'skipping', pexpect.TIMEOUT])
    pex.expect(pexpect.EOF)
    if i == 0:
        logging.getLogger('koji.plugin.sign').info('Package sign successful!')
    elif i == 1:
        logging.getLogger('koji.plugin.sign').error('Pass phrase check failed!')
    elif i == 2:
        logging.getLogger('koji.plugin.sign').error('Package sign skipped!')
    elif i == 3:
        logging.getLogger('koji.plugin.sign').error('Package sign timed out!')
    else:
        logging.getLogger('koji.plugin.sign').error('Unexpected sign result!')
    if i != 0:
        # Rewind in rpm output
        fout.seek(0)
        # Add GPG errors to log
        for line in fout.readlines():
            if 'gpg:' in line:
                logging.getLogger('koji.plugin.sign').error(line.rstrip('\n'))
        fout.close()
        raise Exception, 'Package sign failed!'
    else:
        fout.close()

register_callback('preImport', sign)

