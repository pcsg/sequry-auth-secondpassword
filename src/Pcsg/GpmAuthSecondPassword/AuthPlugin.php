<?php

/**
 * This file contains \Pcsg\GpmAuthSecondPassword\AuthPlugin
 */

namespace Pcsg\GpmAuthSecondPassword;

use Pcsg\GroupPasswordManager\Actors\CryptoUser;
use Pcsg\GroupPasswordManager\Security\Hash;
use Pcsg\GroupPasswordManager\Security\KDF;
use Pcsg\GroupPasswordManager\Security\Keys\Key;
use Pcsg\GroupPasswordManager\Security\MAC;
use Pcsg\GroupPasswordManager\Security\Random;
use Pcsg\GroupPasswordManager\Security\Utils;
use QUI;
use Pcsg\GroupPasswordManager\Security\Interfaces\IAuthPlugin;
use Pcsg\GroupPasswordManager\Security\Handler\Authentication;

/**
 * Class Events
 *
 * @package pcsg/gpmauthsecondpassword
 * @author www.pcsg.de (Patrick Müller)
 */
class AuthPlugin implements IAuthPlugin
{
    const NAME = '2nd Password Authentification';
    const TBL  = 'pcsg_gpm_auth_second_password';

    /**
     * Flag for user password change
     *
     * @var bool
     */
    public static $passwordChange = false;

    /**
     * The authentication information for different users
     *
     * @var array
     */
    protected static $authInformation = array();

    /**
     * Return internal name of auth plugin
     *
     * @return String
     */
    public static function getName()
    {
        return self::NAME;
    }

    /**
     * Authenticate a user with this plugin
     *
     * @param mixed $information
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return true - if authenticated
     * @throws QUI\Exception
     */
    public static function authenticate($information, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!self::isRegistered($User)) {
            // @todo eigenen 401 error code
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.user.not.registered'
            ));
        }

        // get salt
        $result = QUI::getDataBase()->fetch(array(
//            'select' => array(
//                'password_salt'
//            ),
            'from'  => self::TBL,
            'where' => array(
                'userId' => $User->getId()
            )
        ));

        $data = current($result);

        $macData = array(
            $data['userId'],
            $data['password_hash'],
            $data['password_salt'],
            $data['key_salt']
        );

        $macExpected = $data['MAC'];
        $macActual   = MAC::create(
            implode('', $macData),
            Utils::getSystemPasswordAuthKey()
        );

        if (!MAC::compare($macExpected, $macActual)) {
            QUI\System\Log::addCritical(
                self::class . ' authenticate() -> Auth data for user #' . $data['userId'] . ' possibly altered.'
                . ' MAC mismatch!'
            );

            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.user.authentication.data.not.authentic'
            ));
        }

        $salt = $data['password_salt'];

        $hashActual   = Hash::create($information, $salt);
        $hashExpected = self::getPasswordHash($User->getId());

        if (!MAC::compare($hashExpected, $hashActual)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.user.authentication.data.wrong'
            ));
        }

        self::$authInformation[$User->getId()] = $information;

        return true;
    }

    /**
     * Checks if a user is successfully authenticated for this runtime
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return bool
     */
    public static function isAuthenticated($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        return isset(self::$authInformation[$User->getId()]);
    }

    /**
     * Get the derived key from the authentication information of a specific user
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return Key
     * @throws QUI\Exception
     */
    public static function getDerivedKey($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!self::isAuthenticated($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.derive.key.user.not.authenticated'
            ));
        }

        return KDF::createKey(self::$authInformation[$User->getId()], self::getKeySalt($User));
    }

    /**
     * Returns URL QUI\Control that collects authentification information
     *
     * @return string - \QUI\Control URL
     */
    public static function getAuthenticationControl()
    {
        return 'package/pcsg/gpmauthsecondpassword/bin/controls/Authentication';
    }

    /**
     * Change authentication information
     *
     * @param mixed $old - current authentication information
     * @param mixed $new - new authentication information
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     *
     * @return void
     * @throws QUI\Exception
     */
    public static function changeAuthenticationInformation($old, $new, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!self::isRegistered($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.change.auth.user.not.registered'
            ));
        }

        // check old authentication information
        try {
            self::authenticate($old, $User);
        } catch (\Exception $Exception) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.change.auth.old.information.wrong'
            ));
        }

        // check new authentication information
        $new = trim($new);

        if (empty($new)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.change.auth.new.information.empty'
            ));
        }

        // set new user password
        $passwordSalt = Random::getRandomData();
        $passwordHash = Hash::create($new, $passwordSalt);

        $keySalt = Random::getRandomData();

        $macData = array(
            $User->getId(),
            $passwordHash,
            $passwordSalt,
            $keySalt
        );

        $macValue = MAC::create(
            implode('', $macData),
            Utils::getSystemPasswordAuthKey()
        );

        QUI::getDataBase()->update(
            self::TBL,
            array(
                'password_hash' => $passwordHash,
                'password_salt' => $passwordSalt,
                'key_salt'      => $keySalt,
                'MAC'           => $macValue
            ),
            array(
                'userId' => $User->getId()
            )
        );

        self::$authInformation[$User->getId()] = $new;
    }

    /**
     * Get the salt used for key derivation
     *
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return string
     */
    protected static function getKeySalt($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        $result = QUI::getDataBase()->fetch(array(
            'select' => array('key_salt'),
            'from'   => self::TBL,
            'where'  => array(
                'userId' => $User->getId()
            )
        ));

        // @todo ggf. abfragen ob existent
        $salt = $result[0]['key_salt'];

        return $salt;
    }

    /**
     * Registers a user with this plugin
     *
     * @param mixed $information - authentication information given by the user
     * @param \QUI\Users\User $User (optional) - if omitted, use current session user
     * @return string - authentication information
     *
     * @throws QUI\Exception
     */
    public static function register($information, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (self::isRegistered($User)) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.user.already.registered'
            ));
        }

        if (!is_array($information)
            || !isset($information['password'])
            || !isset($information['passwordcheck'])
            || empty($information['password'])
            || empty($information['passwordcheck'])
        ) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.register.invalid.registration.information'
            ));
        }

        $pw      = $information['password'];
        $pwCheck = $information['passwordcheck'];

        if ($pw !== $pwCheck) {
            throw new QUI\Exception(array(
                'pcsg/gpmauthsecondpassword',
                'exception.register.passwords.not.equal'
            ));
        }

        $passwordSalt = Random::getRandomData();
        $passwordHash = Hash::create($pw, $passwordSalt);
        $keySalt      = Random::getRandomData();

        $macData = array(
            $User->getId(),
            $passwordHash,
            $passwordSalt,
            $keySalt
        );

        $macValue = MAC::create(
            implode('', $macData),
            Utils::getSystemPasswordAuthKey()
        );

        QUI::getDataBase()->insert(
            self::TBL,
            array(
                'userId'        => $User->getId(),
                'password_hash' => $passwordHash,
                'password_salt' => $passwordSalt,
                'key_salt'      => $keySalt,
                'MAC'           => $macValue
            )
        );

        return $pw;
    }

    /**
     * Checks if a user is successfully registered with this auth plugin
     *
     * @param QUI\Users\User $User (optional) - if ommitted, use current session user
     * @return bool
     */
    public static function isRegistered($User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        $result = QUI::getDataBase()->fetch(array(
            'count' => 1,
            'from'  => self::TBL,
            'where' => array(
                'userId' => $User->getId()
            )
        ));

        if (current(current($result)) == 0) {
            return false;
        }

        return true;
    }

    /**
     * Get list of User IDs of users that are registered with this plugin
     *
     * @return array
     */
    public static function getRegisteredUserIds()
    {
        $userIds = array();

        $result = QUI::getDataBase()->fetch(array(
            'select' => array(
                'userId'
            ),
            'from'   => self::TBL
        ));

        foreach ($result as $row) {
            $userIds[] = $row['userId'];
        }

        return $userIds;
    }

    /**
     * Returns URL of QUI\Control that collects registration information
     *
     * @return string - \QUI\Control URL
     */
    public static function getRegistrationControl()
    {
        return 'package/pcsg/gpmauthsecondpassword/bin/controls/Registration';
    }

    /**
     * Registers the auth plugin with the main password manager module
     *
     * @return void
     */
    public static function registerPlugin()
    {
        Authentication::registerPlugin(
            self::class,
            self::NAME,
            'Password authentication via second password'
        );
    }

    /**
     * Returns URL of QUI\Control that allows changing of authentication information
     *
     * @return string - \QUI\Control URL
     */
    public static function getChangeAuthenticationControl()
    {
        return 'package/pcsg/gpmauthsecondpassword/bin/controls/ChangeAuth';
    }

    /**
     * Get password hash of user
     *
     * @param integer $userId
     * @return string|false - password hash or false if not found
     */
    protected static function getPasswordHash($userId)
    {
        $result = QUI::getDataBase()->fetch(array(
            'select' => array(
                'password_hash'
            ),
            'from'   => self::TBL,
            'where'  => array(
                'userId' => $userId
            )
        ));

        if (empty($result)) {
            return false;
        }

        return $result[0]['password_hash'];
    }

    /**
     * Delete a user from this plugin
     *
     * @param CryptoUser $CryptoUser
     * @return mixed
     */
    public static function deleteUser($CryptoUser)
    {
        QUI::getDataBase()->delete(
            self::TBL,
            array(
                'userId' => $CryptoUser->getId()
            )
        );
    }
}
