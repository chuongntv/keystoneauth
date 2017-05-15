# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from positional import positional

from keystoneauth1.identity import v3
from keystoneauth1.identity.generic import base


class Totp(base.BaseGenericPlugin):
    """A common user/password authentication plugin.

    :param string username: Username for authentication.
    :param string user_id: User ID for authentication.
    :param string password: Password for authentication.
    :param string user_domain_id: User's domain ID for authentication.
    :param string user_domain_name: User's domain name for authentication.

    """

    @positional()
    def __init__(self, auth_url, username=None, user_id=None, password=None, passcode=None,
                 user_domain_id=None, user_domain_name=None, **kwargs):
        super(Totp, self).__init__(auth_url=auth_url, **kwargs)

        self._username = username
        self._user_id = user_id
        self._passcode = passcode
        self._password = password
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name

    def create_plugin(self, session, version, url, raw_status=None):
        u_domain_id = self._user_domain_id or self._default_domain_id
        u_domain_name = self._user_domain_name or self._default_domain_name

        return v3.TOTP(auth_url=url,
                       user_id=self._user_id,
                       username=self._username,
                       user_domain_id=u_domain_id,
                       user_domain_name=u_domain_name,
                       passcode=self._passcode,
                       password=self._password,
                       **self._v3_params)
