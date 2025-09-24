from __future__ import unicode_literals
import os
import csv
from datetime import datetime
from django.conf import settings
from django.utils.module_loading import import_string as _load
from common import conf
from django.shortcuts import redirect
from django.urls import reverse
import threading

_user = threading.local()

class CurrentUserMiddleware:
    """Middleware to store the current user in thread-local storage."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _user.value = request.user if request.user.is_authenticated else None
        response = self.get_response(request)
        return response

def get_current_user():
    """Utility function to access the current user."""
    return getattr(_user, 'value', None)


class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated and '/accounts/' not in request.path:
            return redirect(reverse('login'))
        response = self.get_response(request)
        return response

"""
user every request / response tracker
"""
def get_ip_address(request):
    for header in conf.IP_ADDRESS_HEADERS:
        addr = request.META.get(header)
        if addr:
            return addr.split(',')[0].strip()


def get_extra_data(request, response, body):
    if not conf.GET_EXTRA_DATA:
        return
    return _load(conf.GET_EXTRA_DATA)(request, response, body)

class ActivityLogMiddleware:
    def __init__(self, get_response=None):
        self.get_response = get_response

    def __call__(self, request):
        request.saved_body = request.body
        if conf.LAST_ACTIVITY and request.user.is_authenticated:
            getattr(request.user, 'update_last_activity', lambda: 1)()

        response = self.get_response(request)

        # Process the response
        self._write_log_to_csv(request, response, getattr(request, 'saved_body', ''))

        return response

    def _write_log_to_csv(self, request, response, body):
        # Skip logging based on existing conditions
        if not self._should_log(request, response):
            return

        # Determine username and prepare filename
        if request.user.is_authenticated:
            username = request.user.get_username()
            user_id = request.user.pk
        elif getattr(request, 'session', None):
            username = f"anon_{request.session.session_key}"
            user_id = 0
        else:
            return

        # Create log entry
        log_entry = [
            datetime.now().isoformat(),
            user_id,
            username,
            request.build_absolute_uri()[:255],
            request.method,
            response.status_code,
            get_ip_address(request),
            get_extra_data(request, response, body)
        ]

        # Create or append to CSV file
        self._log_to_csv_file(username, log_entry)

    def _log_to_csv_file(self, username, log_entry):
        today_date = datetime.now().strftime('%Y-%m-%d')
        directory = os.path.join(os.path.dirname(settings.BASE_DIR), 'activity_logs')
        os.makedirs(directory, exist_ok=True)

        # Determine filename based on authentication state
        if username.startswith("anon_"):
            filename = os.path.join(directory, f"{username}_{today_date}.csv")
        else:
            filename = os.path.join(directory, f"{username}_{today_date}.csv")

        # Check if file exists and write accordingly
        file_exists = os.path.isfile(filename)

        with open(filename, mode='a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # Write header only if file is being created for the first time
            if not file_exists:
                writer.writerow(['Timestamp', 'User ID', 'Username', 'Request URL',
                                 'Request Method', 'Response Code',
                                 'IP Address', 'Extra Data'])
            writer.writerow(log_entry)

    def _should_log(self, request, response):
        miss_log = [
            not (conf.ANONIMOUS or request.user.is_authenticated),
            request.method not in conf.METHODS,
            any(url in request.path for url in conf.EXCLUDE_URLS)
        ]

        if conf.STATUSES:
            miss_log.append(response.status_code not in conf.STATUSES)

        if conf.EXCLUDE_STATUSES:
            miss_log.append(response.status_code in conf.EXCLUDE_STATUSES)

        return not any(miss_log)
