# CIS Provider

A CIS (Change Integration Service) Provider is the piece of software that provides CIS with change requests.
For example, Mozillians.org - the user profile management web interface - sends a message to CIS asking to change the t-shirt size
of a user. Mozillians.org therefore acts as a CIS Provider.

## Provider requirements

This is the list of features that the Provider **must** support to talk to CIS:

1. Send accurate full-data user profiles. This means that for each change, the complete user profile data is required (all fields are required).
  * The integration will not occur (i.e. user profile change will fail validation) if:
    * Critical data, such as the `user_id` field is missing.
    * Any user-profile field is missing.
    * The Provider attempts to change the values of a protected field (e.g.: Mozillians.org changes the WorkDay Staff group data instead of echo'ing the current value).
  * CIS requires the Provider to make reasonable efforts in providing an up to date and accurate user profile.
  * If a field is present and the value is empty (e.g.: "groups": "") then the field of the user profile will be integrated as empty (removed from all groups).

2. Cryptographically sign the user profile.
  * The profile **must** be signed with a key trusted by CIS (CIS white-lists authorized providers).
  * The profile signature can be validated by RP (Relying Parties).
  * The profile **may** be signed by more keys.

3. Ensure message validation succeed by consuming the response from CIS.
  * Optionally send back the message (after updating it) on failure, for example by re-fetching the latest version of the user profile.
