# -*- coding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals

from sys import version_info

import flask_login
from flask_login import login_required, current_user, logout_user

from airflow import settings
from airflow import models
from airflow.utils.log.logging_mixin import LoggingMixin
import os

log = LoggingMixin().log

class AuthenticationError(Exception):    
        pass

class ProxiedUser(models.User):
    def __init__(self, user):
        self.user = user

    def is_active(self):
        '''Required by flask_login'''
        return True

    def is_authenticated(self):
        '''Required by flask_login'''
        return True

    def is_anonymous(self):
        '''Required by flask_login'''
        return False
        
    def get_id(self):
        '''Returns the current user id as required by flask_login'''
        return self.user.get_id()

    def data_profiling(self):
        '''Provides access to data profiling tools'''
        return True

    def is_superuser(self):
        '''Access all the things'''
        return True

class ProxiedAuth(object):
    def __init__(self):
        self.login_manager = flask_login.LoginManager()

    def init_app(self,flask_app):
        self.flask_app = flask_app
        self.login_manager.init_app(self.flask_app)

        #checks headers instead of cookies
        self.login_manager.request_loader(self.load_request)

        # this is needed to disable the anti forgery check 
        flask_app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    
    def load_request(self, request):
        '''
        Reads the header field that has already been verified on the
        nginx side by google auth. Header field is specified by setting
        the environment variable AIRFLOW_PROXIED_AUTH_HEADER or else
        it's defaulted to X-Email.

        '''
        session = settings.Session()
        header_field = os.getenv('AIRFLOW_PROXIED_AUTH_HEADER', 'X-Email')
        user_email = request.headers.get(header_field)

        # this shouldn't happen since nginx should take care of it!
        if user_email is None:
            raise AuthenticationError(
                  'Airflow failed to get autheticate used with proxied authentication.\
                  This might mean the headers were set incorrectly')

        # insert user into database if doesn't exist
        user = session.query(models.User)
        .filter(
            models.User.username == user_email).first()

        if not user:
            user = models.User(
                username=user_email,
                is_superuser=True)

        session.merge(user)
        session.commit()
        session.close()

        return ProxiedUser(user)

login_manager = ProxiedAuth()


