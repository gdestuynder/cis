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

    # Validate only whitelisted fields for this publisher are in use
    whitelist = [
        'timezone',
        'displayName',
        'firstName',
        'lastName',
        'preferredLanguage',
        'primaryEmail',
        'emails',
        'phoneNumbers',
        'uris',
        'nicknames',
        'SSHFingerprints',
        'PGPFingerprints',
        'picture',
        'shirtSize',
        'groups',
        'tags'
    ]

    pv = validation.ProfileValidation(publisher="mozilliansorg",
                           current_profile=vault_json,
                           new_profile=profile_json,
                           attribute_whitelist=whitelist)

    # Allows user creation by this publisher.
    pv.permissions['CAN_CREATE_USER'] = True  # XXX TBD turn this back to false when there is another method of user provision.
    pv.permissions['ENFORCE_ATTR_WHITELIST'] = False

    if not pv.verify_publisher(publisher):
        return True

    return pv.validate():
