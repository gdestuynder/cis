# Using the CIS Person API endpoint

## What is CIS Person API?

The CIS (Change Integration Service) Person API is a read-only API to get access to the user database (Vault).

This is CIS Person API v2 (version 2).

## What are the access controls around CIS Person API?

CIS Person API requires credentials for most routes (i.e. all routes that may expose non-PUBLIC data).
It leverages Mozilla's data classification to decide which kind of data is to be returned, and will filter out anything
that does not match the classification levels you have been granted access to.

See also: https://wiki.mozilla.org/Security/Data_Classification

You can check which fields of a user can be accessed with which classification here:
https://auth.mozilla.com/.well-known/profile.schema (or in
[cis_profile](../python-modules/cis_profile/cis_profile/data/user_profile_null.json) which can be slightly easier to
read. Pro-tip, you can load this in a JSON viewer (Search for JSON viewer on the web). Pro-tip, you can load this in a
JSON viewer (Search for JSON viewer on the web).

Data may also optionally be filtered by display level, which is the level a user request the data to be filtered at, for
displaying purposes.

## How do I get credentials for access?

Please file a request at https://mozilla.service-now.com/sp?id=sc_cat_item&sys_id=1e9746c20f76aa0087591d2be1050ecb

Indicate your use case, and the fields you need to access and/or their data classification and display level.

For example:

> I need access to the office location of all employees (classification: STAFF CONFIDENTIAL, display: staff) so that I can send messages about when
> their office will be closed during the holidays.


Depending on the request, it's possible that we follow-up with a rapid risk assessment
(https://infosec.mozilla.org/guidelines/risk/rapid_risk_assessment), or simply grant the access.


NOTE: If no use case or user story with a rational is present, no access will be granted to NON-PUBLIC data!


The credentials you will receive are OAuth2 credentials.

## Do you have code examples?

Yes, please look at our [end to end (E2E) tests](../e2e).

Here's a quick curl example as well:
```
# Get a token
$ curl -X POST -H "Content-Type: application/json" https://auth.mozilla.auth0.com/oauth/token -d \
'{"audience":"api.sso.mozilla.com","scope":"classification:staff_confidential display:staff",\
"response_type":"client_credentials","client_id": "YOUR CLIENT ID", "client_secret": "YOUR CLIENT SECRET"}'

# Use the token
$ curl -H  "Authorization: Bearer YOUR_TOKEN_HERE" https://person.api.sso.mozilla.com/v2/user/primary_email/some_email@email.com
```

## What are the available scopes exactly?

The scope list is available [here](../well-known-endpoint/auth0-helper/scopes.json).

## What is the API URL?

You can find it here: https://auth.mozilla.com/.well-known/mozilla-iam (look for person api).

## What routes are available? (i.e. what queries can I make)

The easiest is to mimic the E2E tests, otherwise:

Retrieve specific user profiles:
- `/v2/user/user_id/<string:user_id>`
- `/v2/user/uuid/<string:uuid>`
- `/v2/user/primary_email/<string:primary_email>`
- `/v2/user/primary_username/<string:primary_username>`

Retrieve lists of users:
- `/v2/users/id/all?[connectionMethod=ad]` (Returns all user ids for a specific login/connection method)

## I want to help add features to this API!

Hey, that's great! Please look at [cis_profile_retrieval_service](../python-modules/cis_profile_retrieval_service) and send
us a PR!


# FAQ (Frequently Asked Questions)

- I updated my name in the old Phonebook but the change does not appear in CIS Person API, why is that?
CIS will allow certain publishers to write the attribute when the user is created, but not update it. Preferred names for example are created by LDAP (old Phonebook) but then owned by Dinopark. Once created, these can only be modified by DinoPark.
When the old Phonebook is retired, this will no longer be an issue.

- How often is the user profile data refreshed by publishers?
CIS uses a batch-and-event model, which means certain changes happen very quickly (seconds) as an event occurs, while other changes may take longer (batches every 5,10,15 minutes for example).
All writes should attempt to use both batch and event, to provide the best mix of latency and reliability.