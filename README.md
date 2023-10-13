# koji-plugin-sign
Koji plugin for automated package signing; internally used by the OSG Software Team.

This provides a koji-hub preImport plugin that makes a callout to rpmsign(8) to sign the built RPMs before importing them into Koji.
The key IDs and passphrases can be configured via a Python ConfigParser-style config file.
pexpect is used to type in the passphrase or PIN.

This was originally taken from https://fedorahosted.org/koji/ticket/203 but that URL is gone.
The original license is unknown.
