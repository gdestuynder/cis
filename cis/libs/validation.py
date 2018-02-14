import logging
import os

from pluginbase import PluginBase


logger = logging.getLogger(__name__)


class Schema(object):
    def __init__(self, publisher, profile_data, user=None):
        """Validates a user profile against the JSON schema using a predefined set of plugins."""
        # List of plugins to load, in order
        self.plugin_load = ['json_schema_plugin', 'mozilliansorg_publisher_plugin']
        self.plugin_source = self._initialize_plugin_source()
        self.profile_data = profile_data
        self.publisher = publisher
        self.user = user

    def validate(self):
        with self.plugin_source:
            for plugin in self.plugin_load:
                cur_plugin = self.plugin_source.load_plugin(plugin)
                try:
                    if cur_plugin.run(self.publisher, self.user, self.profile_data) is False:
                        return False
                    else:
                        pass
                except Exception as e:
                    logger.exception(
                        'Validation plugin {name} failed : {error}'.format(
                            name=cur_plugin.__name__,
                            error=e
                        )
                    )
                    return False
        return True

    def _initialize_plugin_source(self):
        plugin_base = PluginBase(package='cis.plugins.validation')
        plugin_source = plugin_base.make_plugin_source(
            searchpath=[
                os.path.join(
                    os.path.abspath(
                        os.path.dirname(__file__)
                    ),
                    '../plugins/validation/'
                )
            ]
        )

        return plugin_source


class Operation(object):
    """Guaranteed object for performing validation steps."""
    def __init__(self, publisher, profile_data, user=None):
        self.publisher = publisher
        self.profile_data = profile_data
        self.user = user

    def is_valid(self):
        """Source of truth for all validation options."""
        s = Schema(self.publisher, self.profile_data, self.user)

        if s.validate() is True:
            return True
        else:
            return False

class ProfileValidation():
    """
    Various validation functions, implemented in a generic way for all plugins to use.
    """
    def __init__(self, publisher, current_profile, new_profile, attributes_whitelist):
        """
        :publisher: The publisher this validation plugin cares for
        :current_profile: User profile from the vault
        :new_profile: User profile passed by publisher
        :attributes_whitelist: The attributes we're allowed to change
        """
        self.publisher = publisher
        self.attributes_whitelist = attributes_whitelist
        self.current_profile = current_profile
        self.new_profile = new_profile

        # Validate that only whitelisted accounts/profiles issued from vetted IdPs (generally, the ones enforcing MFA)
        # can get groups assigned as these are used for access control. We do not allow anyone else to set groups.
        # This is used by function _check_groups() but defined here for convenience
        self.whitelist_idp_with_enforced_mfa = [
            'github|',  # GitHub has a rule in Auth0 to enforce MFA
            'ad|'       # = LDAP which enforces Duo MFA in Auth0
        ]

        # Default permissions
        self.permissions = {
                'CAN_CREATE_USER': False,
                'ENFORCE_ATTR_WHITELIST': True
        }


    def verify_publisher(self, publisher):
        """
        Checks if we care to validate for this publisher
        :publisher: The publisher currently processing profile change
        """
        if self.publisher != publisher:
            logger.debug("Validation plugin registered for {}, skipping publisher {}".format(self.publisher,
                                                                                             publisher))
            return False
        return True

    def _check_basic(self):
        """
        Basic checks that may never fail regardless of publisher
        Returns True on success
        """

        # Does user exist at all?
        if self.current_profile is None:
            if self.permissions.get('CAN_CREATE_USER') == False:
                logger.exception('permission denied: publisher {} attempted to modify user that does not exist'
                                 ' in the identity vault'.format(self.publisher))
                return False
            else:
                logger.warning('Allowing new user profile creation for publisher {}'.format(self.publisher))

        if self.new_profile is None:
            logger.exception('no new profile provided by publisher {}. This is fatal!'.format(self.publisher))
            return False
        return True

    def _check_attributes(self):
        """
        Checks the publisher modifies attributes it has authority over
        """
        if self.permissions.get('ENFORCE_ATTR_WHITELIST') == False:
            logger.warning('Bypassing attributes whitelisting for publisher {}'.format(self.publisher))
            return True

        for attr in self.current_profile:
            if attr not in self.attributes_whitelist:
                if self.new_profile.get(attr) != self.current_profile.get(attr):
                    logger.exception('permission denied: publisher {} attempted to modify user attributes it has no'
                                     'authority over'.format(self.publisher))
                    return False
        return True

    def _check_groups(self):
        old_groups = current_profile.get('groups', [])
        new_groups = new_profile.get('groups', [])

        for profile_idp in self.whitelist_idp_with_enforced_mfa:
            if not new_profile.get('user_id').startswith(profile_idp):
                if new_groups:
                    logger.exception('permission denied: publisher {} attempted to set `groups` attribute values for '
                                     'a user profile initiated by an IdP that is not allowed to use '
                                     '`groups`'.format(self.publisher))
                    return False

        # Also check is we have any group that has been *removed*
        for g in old_groups:
            if not g.startswith(prefix):
                if g not in new_groups:
                    logger.exception('permission denied: publisher {} attempted to remove groups it has no authority over'
                                     .format(self.publisher))
                    return False

        # Also check is we have any group that has been *added*
        for g in new_groups:
            if not g.startswith(prefix):
                if g not in old_groups:
                    logger.exception('permission denied: publisher {} attempted to add groups it has no authority over'
                                     .format(self.publisher))
                    return False
        return True

    def validate(self):
        """
        Return True is validation is successful
        """
        if not self._check_basic():
            return False
        if not self._check_attributes():
            return False
        if not self._check_groups():
            return False
        logger.info('Validation successful for publisher {}'.format(self.publisher))
        return True
