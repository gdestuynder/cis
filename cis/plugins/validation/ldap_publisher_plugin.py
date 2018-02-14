import logging

from cis.libs import utils
from cis.libs import validation

utils.StructuredLogger(name=__name__, level=logging.INFO)
logger = logging.getLogger(__name__)

def run(publisher, vault_json, profile_json):
    """
    Returns True if validation succeeded, False if not (profile change will not be propagated)
    :publisher: The CIS publisher
    :user: The user from the CIS vault
    :profile_json: The user profile passed by the publisher
    """

    # The attributes we're allowed to change
    whitelist = [
        'groups'
    ]
    pv = validation.ProfileValidation(publisher="ldap",
                           current_profile=vault_json,
                           new_profile=profile_json,
                           attribute_whitelist=whitelist)
    if not pv.verify_publisher(publisher):
        return True

    return pv.validate():
