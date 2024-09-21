#!/usr/bin/env python3
""" Implementation that adds an experation date to session_id """
from api.v1.auth.session_auth import SessionAuth
from os import environ
from datetime import datetime, timedelta
from models.user import User


class SessionExpAuth(SessionAuth):
    """ Extension of SessionAuth that handles experation of session_id """

    def __init__(self):
        "Overload of Auth (auth.py) class init function"
        duration_status = True
        SESSION_DURATION = environ.get('SESSION_DURATION')
        if SESSION_DURATION is None:
            duration_status = False
        try:
            SESSION_DURATION = int(SESSION_DURATION)
        except Exception:
            duration_status = False
        if duration_status is False:
            SESSION_DURATION = 0

        self.session_duration = SESSION_DURATION

    def create_session(self, user_id=None):
        """
        [summary] - Overload of SessionAuth(session_auth.py)
        class method create_session
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        session_dictionary = {"user_id": user_id, "created_at": datetime.now()}
        self.user_id_by_session_id[session_id] = session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """ Get a user_id from a session_id """
        if session_id is None:
            return None
        if session_id not in self.user_id_by_session_id:
            return None

        session_dictionary = self.user_id_by_session_id.get(session_id)

        if self.session_duration <= 0:
            return session_dictionary.get('user_id')
        if 'created_at' not in session_dictionary:
            return None
        time_difference = timedelta(seconds=self.session_duration) + \
            session_dictionary['created_at']
        if datetime.now() > time_difference:
            return None
        return session_dictionary.get('user_id')
