<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 */

use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;

/**
 * Session provider for apache/authz authenticated users.
 *
 * Class AuthProductOpener
 */
class AuthProductOpener extends MediaWiki\Session\ImmutableSessionProviderWithCookie {

    /**
     * @param array $params Keys include:
     *  - priority: (required) Set the priority
     *  - sessionCookieName: Session cookie name. Default is '_AuthProductOpenerSession'.
     *  - sessionCookieOptions: Options to pass to WebResponse::setCookie().
     */
    public function __construct(array $params = []) {
        if (!isset($params['sessionCookieName'])) {
            $params['sessionCookieName'] = '_AuthProductOpenerSession';
        }
        parent::__construct( $params );

        if ( !isset( $params['priority'] ) ) {
            throw new \InvalidArgumentException(__METHOD__ . ': priority must be specified');
        }
        if ($params['priority'] < SessionInfo::MIN_PRIORITY ||
            $params['priority'] > SessionInfo::MAX_PRIORITY
        ) {
            throw new \InvalidArgumentException(__METHOD__ . ': Invalid priority');
        }

        $this->priority = $params['priority'];
    }

    /**
     * @inheritDoc
     */
    public function provideSessionInfo(WebRequest $request)
    {
        // Have a session ID?
        $id = $this->getSessionIdFromCookie($request);
        // #6 assign a new sessionid if the id is null or if the session is no longer valid
        if ((null === $id)||(!MediaWiki\Session\SessionManager::singleton()->getSessionById($id))) {
            $poUserInfo = $this->getRemoteUserInfo();
            $sessionInfo = $this->newSessionForRequest($poUserInfo, $request);

            return $sessionInfo;
        }

        $sessionInfo = new SessionInfo($this->priority, [
            'provider' => $this,
            'id' => $id,
            'persisted' => true
        ]);

        return $sessionInfo;
    }

    /**
     * @inheritDoc
     */
    public function newSessionInfo($id = null)
    {
        return null;
    }

    /**
     * @param array $poUserInfo
     * @param WebRequest $request
     * @return SessionInfo
     */
    protected function newSessionForRequest($poUserInfo, WebRequest $request)
    {
        if ($poUserInfo === null || !isset($poUserInfo['user_id'])) {
            return null;
        }

        $profile = $this->getSsoUserData($poUserInfo);
        if ($profile === null) {
            return null;
        }

        $id = $this->getSessionIdFromCookie($request);

        $user = User::newFromName($profile->{'user_id'}, 'usable');
        if (!$user) {
            throw new \InvalidArgumentException('Invalid user name');
        }

        $this->initUser($user, $profile);

        $info = new SessionInfo(SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => UserInfo::newFromUser($user, true),
            'persisted' => false
        ]);
        $session = $this->getManager()->getSessionFromInfo($info, $request);
        $session->persist();

        return $info;
    }

    /**
     * When creating a user account, optionally fill in
     * preferences and such.  For instance, you might pull the
     * email address or real name from the external user database.
     *
     * @param $user User object.
     * @param $profile user profile
     */
    protected function initUser(&$user, $profile)
    {
        if (Hooks::run("AuthRemoteUserInitUser",
            array($user, true))
        ) {
            // Check if above hook or some other effect (e.g.: https://phabricator.wikimedia.org/T95839 )
            // already created a user in the db. If so, reuse that one.
            $userFromDb = $user->getInstanceForUpdate();
            if (null !== $userFromDb) {
                $user = $user->getInstanceForUpdate();
            }

            $this->setRealName($user, $profile);

            $this->setEmail($user, $profile);

            $user->mEmailAuthenticated = wfTimestampNow();
            $user->setToken();

            $this->setNotifications($user);
        }

        $user->saveSettings();
    }

    /**
     * Sets the real name of the user.
     *
     * @param User
     * @param array
     */
    protected function setRealName(User $user, $profile)
    {
        $user->setRealName($profile->{'name'});
    }

    /**
     * Return the SSO cookie data to be used as an array.  Empty array if none.
     *
     * @return array
     */
    protected function getRemoteUserInfo()
    {
        global $wgAuthProductOpenerCookieName;

        if (isset($_COOKIE[$wgAuthProductOpenerCookieName])) {
            $cookie = $_COOKIE[$wgAuthProductOpenerCookieName];
            if ( $cookie === null || $cookie === '' || $cookie === 'deleted') {
                $this->logger->notice('No session cookie found for request.');
                return null;
            }

            $this->logger->debug('Session cookie found for request: {cookie}.',
            [
                'cookie' => $cookie
            ]);

            $chunks = array_chunk(preg_split('/&/', $cookie), 2);
            $data = array_combine(array_column($chunks, 0), array_column($chunks, 1));
            return $data;
        } else {
            return null;
        }
    }

    /**
     * Sets the email address of the user.
     *
     * @param User
     * @param array user profile
     */
    protected function setEmail(User $user, $profile)
    {
        $user->setEmail($profile->{'email'});
    }

    /**
     * Set up notifications for the user.
     *
     * @param User
     */
    protected function setNotifications(User $user)
    {
        global $wgAuthProductOpenerNotify;

        // turn on e-mail notifications
        if ($wgAuthProductOpenerNotify) {
            $user->setOption('enotifwatchlistpages', 1);
            $user->setOption('enotifusertalkpages', 1);
            $user->setOption('enotifminoredits', 1);
            $user->setOption('enotifrevealaddr', 1);
        }
    }

    /**
     * Validate SSO session id and get user profile from the Product Opener server
     *
     * @param array $poUserInfo
     */
    protected function getSsoUserData($poUserInfo)
    {
        global $wgAuthProductOpenerDomain;

        try {
            $url = 'https://' . $wgAuthProductOpenerDomain . '/cgi/sso.pl';
            $this->logger->debug('Validating auth cookie {cookie} from {url}.',
            [
                'cookie' => $poUserInfo,
                'url' => $url,
             ]);

            $response = Http::post( $url,  [ "postData" => $poUserInfo ] );
            if ($response === false) {
                $this->logger->notice('SSO response for cookie {cookie} was {response}.',
                [
                    'cookie' => $poUserInfo,
                    'response' => $response,
                ]);
                return null;
            }

            $this->logger->debug('SSO response for cookie {cookie} was {response}.',
            [
                'cookie' => $poUserInfo,
                'response' => $response,
            ]);
            return json_decode($response);
        } catch (HttpException $ex) {
            $this->logger->error('Could not retrieve user information for session cookie.',
            [
                'cookie' => $poUserInfo
            ]);
        }
    }
}
