#!/usr/bin/env python3

# mastosync allows you to sync your Mastodon toots to your Twitter account.
# Copyright (C) 2020 Lorenzo Gil Sanchez

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import configparser
import datetime
import functools
import hmac
import html.parser
import json
import operator
import os.path
from urllib.error import HTTPError
from urllib.parse import quote, urljoin
from urllib.request import urlopen, Request
import secrets
import sys
import time
from typing import Any, cast, Dict, List, Optional


def parse_timedelta(deltastring: str) -> datetime.timedelta:
    stripped = deltastring.strip()
    number = stripped
    lastchar = stripped[-1]
    delta_types_dict = dict(
        d='days', s='seconds', m='minutes', h='hours', w='weeks'
    )
    delta_type = delta_types_dict.get(lastchar)
    if delta_type is None:
        if lastchar.isdigit():
            delta_type = 'days'  # default delta type
        else:
            raise ValueError(
                'Invalid suffix {} when parsing timedelta: "{}"'.format(
                    lastchar, deltastring
                )
            )
    else:
        number = stripped[:-1]

    try:
        delta_value = int(number)
    except ValueError:
        raise ValueError(
            'Invalid numeric value {} when parsing timedelta: "{}"'.format(
                number, deltastring
            )
        )

    timedelta_args = {delta_type: delta_value}
    return datetime.timedelta(**timedelta_args)


class ConfigError(Exception):
    pass


class Configuration:

    TWITTER_SECTION = 'twitter'
    MASTODON_SECTION = 'mastodon'

    def __init__(self) -> None:
        self.config = configparser.ConfigParser()
        config_locations = [
            os.path.join(
                os.path.expanduser('~'),
                '.config',
                'mastosync',
                'mastosync.ini'
            ),
        ]

        for configfile in config_locations:
            if os.path.exists(configfile):
                self.config.read(configfile)
                break
        else:
            raise ConfigError(
                'Could not find a configuration file in '
                'any of these locations: {}'.format(
                    ', '.join(config_locations)
                )
            )

        if self.TWITTER_SECTION not in self.config:
            raise ConfigError(
                'Missing section "{}" in the config file.'.format(
                    self.TWITTER_SECTION
                )
            )

        twitter_opt = functools.partial(
            self._read_option,
            self.config[self.TWITTER_SECTION], self.TWITTER_SECTION
        )

        self.twitter_screen_name = twitter_opt('screen_name')
        self.twitter_api_key = twitter_opt('api_key')
        self.twitter_api_secret_key = twitter_opt('api_secret_key')
        self.twitter_access_token = twitter_opt('access_token')
        self.twitter_access_token_secret = twitter_opt('access_token_secret')

        if self.MASTODON_SECTION not in self.config:
            raise ConfigError(
                'Missing section "{}" in the config file.'.format(
                    self.MASTODON_SECTION
                )
            )

        mastodon_opt = functools.partial(
            self._read_option,
            self.config[self.MASTODON_SECTION], self.MASTODON_SECTION
        )

        self.mastodon_base_url = mastodon_opt('base_url')
        self.mastodon_account_id = mastodon_opt('account_id')
        time_threshold = mastodon_opt('time_threshold', '1w')
        self.mastodon_time_threshold = parse_timedelta(time_threshold)

    def _read_option(
            self,
            section: configparser.SectionProxy,
            section_name: str,
            option_name: str,
            default: Optional[Any] = None,
    ) -> str:
        option = ''
        if option_name in section:
            option = section[option_name]
            if not option:
                raise ConfigError(
                    'Option "{}" from section "{}" can not be empty.'.format(
                        option_name, section_name
                    )
                )
        elif default is None:
            raise ConfigError(
                'Could not find option "{}" inside section "{}".'.format(
                    section_name, option_name,
                )
            )
        else:
            option = default

        return option


def quote_safe(data: str) -> str:
    return quote(data, safe='')


def encode_params(params: Dict[str, str]) -> str:
    param_list = []
    for key in sorted(params.keys()):
        value = params[key]
        param_item = '{}={}'.format(quote_safe(key), quote_safe(value))
        param_list.append(param_item)

    param_string = '&'.join(param_list)
    return param_string


def get_twitter_authorization_header(oauth_params: Dict[str, str]) -> str:
    result = ', '.join(
        ['{}="{}"'.format(quote_safe(key), quote_safe(value))
         for key, value in oauth_params.items()]
    )

    return 'OAuth ' + result


class BaseSession:

    def get_headers(
            self,
            url: str,
            method: str,
            params: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        return {}

    def request(
            self,
            url: str,
            method: str,
            params: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        if params:
            param_string = encode_params(params)
        else:
            param_string = ''

        if param_string:
            full_url = url + '?' + param_string
        else:
            full_url = url

        headers = self.get_headers(url, method, params)

        req = Request(full_url, None, headers=headers, method=method)
        try:
            response = urlopen(req)
            response_content = cast(Dict[str, str], json.load(response))
        except HTTPError as error:
            print(error.read())
            raise

        return response_content


class TwitterSession(BaseSession):

    def __init__(
            self,
            api_key: str,
            api_secret_key: str,
            access_token: str,
            access_token_secret: str
    ) -> None:
        self.api_key = api_key
        self.api_secret_key = api_secret_key
        self.access_token = access_token
        self.access_token_secret = access_token_secret

    def _get_signature(
            self,
            url: str,
            method: str,
            params: Dict[str, str]
    ) -> bytes:
        param_string = encode_params(params)

        signature_base_string = '{}&{}&{}'.format(
            method.upper(),
            quote_safe(url),
            quote_safe(param_string)
        ).encode('ascii')

        signing_key = '{}&{}'.format(
            quote_safe(self.api_secret_key),
            quote_safe(self.access_token_secret)
        ).encode('ascii')

        signature = hmac.new(
            signing_key, signature_base_string, 'sha1'
        ).digest()
        return base64.b64encode(signature)

    def get_headers(
            self,
            url: str,
            method: str,
            params: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        nonce = secrets.token_urlsafe(32)
        timestamp = int(time.time())

        oauth_params = {
            'oauth_consumer_key': self.api_key,
            'oauth_nonce': nonce,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(timestamp),
            'oauth_token': self.access_token,
            'oauth_version': '1.0',
        }
        if params:
            all_params = dict(params)  # make copy
            all_params.update(oauth_params)
        else:
            all_params = oauth_params

        signature = self._get_signature(url, method, all_params)
        oauth_params['oauth_signature'] = signature.decode('ascii')
        authorization = get_twitter_authorization_header(oauth_params)
        headers = {
            'Authorization': authorization,
        }
        return headers


class Post:

    def __init__(
            self,
            id: str,
            created_at: datetime.datetime,
            content: str
    ) -> None:
        self.id = id
        self.created_at = created_at
        self.content = content
        self.raw_content = content.replace('\n', '')

    def __repr__(self) -> str:
        return '<Post id={} time={} content="{}">'.format(
            self.id, self.created_at, self.content[:50]
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Post):
            raise NotImplementedError

        return self.raw_content == other.raw_content


class TwitterAPI:

    def __init__(self, twitter_session: TwitterSession) -> None:
        self.twitter_session = twitter_session

    def get_tweets(self, screen_name: str) -> Dict[str, str]:
        url = 'https://api.twitter.com/1.1/statuses/user_timeline.json'
        data = self.twitter_session.request(
            url, 'GET', {'screen_name': screen_name}
        )
        return data

    def get_posts(self, screen_name: str) -> List[Post]:
        tweets_list = self.get_tweets(screen_name)

        posts = [self._tweet_to_post(tweet)
                 for tweet in tweets_list
                 if self._is_original(tweet)]

        return posts

    def _is_original(self, tweet: Dict[str, str]) -> bool:
        return (
            tweet['retweeted'] is False and
            tweet['in_reply_to_status_id'] is None
        )

    def _tweet_to_post(self, tweet: Dict[str, Any]) -> Post:
        created_at_str = tweet['created_at']
        created_at = datetime.datetime.strptime(
            created_at_str, '%a %b %d %H:%M:%S %z %Y'
        )

        text = tweet['text']
        entities = tweet['entities']
        for url in entities.get('urls', []):
            text = text.replace(url['url'], url['expanded_url'])

        return Post(tweet['id_str'], created_at, text)

    def create_tweet(self, content: str) -> Post:
        url = 'https://api.twitter.com/1.1/statuses/update.json'
        data = self.twitter_session.request(
            url, 'POST', {'status': content}
        )
        return self._tweet_to_post(data)


class HTMLTagStripper(html.parser.HTMLParser):

    def __init__(self) -> None:
        self.reset()
        self.strict = False
        self.convert_charrefs = True
        self.fed: List[str] = []

    def handle_data(self, d: str) -> None:
        self.fed.append(d)

    def handle_endtag(self, t: str) -> None:
        if t == 'p':
            self.fed.append('\n')

    def get_data(self) -> str:
        return ''.join(self.fed)


def strip_tags(html: str) -> str:
    parser = HTMLTagStripper()
    parser.feed(html)
    return parser.get_data().strip()


class MastodonAPI:

    def __init__(self, base_url: str, mastodon_session: BaseSession) -> None:
        self.base_url = base_url
        self.mastodon_session = mastodon_session

    def get_toots(self, account_id: str) -> Dict[str, str]:
        path = '/api/v1/accounts/{}/statuses'.format(account_id)
        url = urljoin(self.base_url, path)
        data = self.mastodon_session.request(url, 'GET')
        return data

    def get_posts(self, account_id: str) -> List[Post]:
        toots_list = self.get_toots(account_id)

        posts = [self._toot_to_post(toot)
                 for toot in toots_list
                 if self._is_original(toot)]

        return posts

    def _is_original(self, toot: Dict[str, str]) -> bool:
        return toot['reblog'] is None and toot['in_reply_to_id'] is None

    def _toot_to_post(self, toot: Dict[str, str]) -> Post:
        created_at_str = toot['created_at'].replace('Z', '+00:00')
        created_at_time = datetime.datetime.fromisoformat(created_at_str)
        content = strip_tags(toot['content'])
        return Post(toot['id'], created_at_time, content)


def get_recent_posts(
        posts: List[Post],
        threshold: datetime.timedelta
) -> List[Post]:
    posts.sort(key=operator.attrgetter('created_at'), reverse=True)

    # only take the ones newer than the threshold
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    recent_posts = [p for p in posts if (now - p.created_at) < threshold]

    return recent_posts


def get_unpublished_posts(
        posts_list: List[Post],
        published_posts_list: List[Post]
) -> List[Post]:
    result = []
    for post in posts_list:
        for published_post in published_posts_list:
            if published_post == post:
                break  # found, no need to publishe it
        else:
            result.append(post)

    return result


def main() -> None:
    try:
        config = Configuration()
    except ConfigError as e:
        sys.stderr.write(str(e) + '\n')
        exit(1)

    twitter_session = TwitterSession(
        config.twitter_api_key,
        config.twitter_api_secret_key,
        config.twitter_access_token,
        config.twitter_access_token_secret,
    )
    twitter_api = TwitterAPI(twitter_session)
    twitter_posts = twitter_api.get_posts(config.twitter_screen_name)

    mastodon_session = BaseSession()
    mastodon_api = MastodonAPI(config.mastodon_base_url, mastodon_session)
    mastodon_posts = mastodon_api.get_posts(config.mastodon_account_id)

    recent_posts = get_recent_posts(
        mastodon_posts, config.mastodon_time_threshold
    )
    post_to_sync = get_unpublished_posts(recent_posts, twitter_posts)

    for post in post_to_sync:
        print('Syncing Mastodon post to Twitter: {}'.format(post.content))
        print(twitter_api.create_tweet(post.content))


if __name__ == '__main__':
    main()
