# Koji callback for writing signed rpms after signing via sign.py
# Required for package generation with strict keys in mash

from koji.plugin import register_callback
import kojihub
import logging
from configparser import ConfigParser

# Configuration file in /etc like for other plugins
config_file = '/etc/koji-hub/plugins/sign.conf'


def post_sign(cbType, sigkey=None, sighash=None, build=None, rpm=None):
    """ Run the kojihub write-signed-rpm command on rpms after they've been signed with a signing key,
    which is required for generating repos that use a specific key.
    """
    buildroot = kojihub.get_buildroot(rpm['buildroot_id'])
    tag_name = buildroot['tag_name']
    logging.getLogger('koji.plugin.sign').info("Running post-sign plugin for package with tag_name %s", tag_name)

    config = ConfigParser()
    config.read(config_file)
    
    if not config.has_option(tag_name, "strict_keys") or not config.getboolean(tag_name, "strict_keys"):
        # Only need to write-signed-rpm for repos with strict signing enabled
        logging.getLogger('koji.plugin.sign').info("tag_name %s doesn't have strict signing enabled. Skipping.", tag_name)
        return
    

    kojihub.write_signed_rpm(rpm, sigkey)
    logging.getLogger('koji.plugin.sign').info("write-signed-rpm task run successfully.")

register_callback('postRPMSign', post_sign)
