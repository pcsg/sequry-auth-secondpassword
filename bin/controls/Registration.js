/**
 * Control for creating a new password
 *
 * @module package/pcsg/gpmauthsecondpassword/bin/controls/Registration
 * @author www.pcsg.de (Patrick Müller)
 *
 * @require qui/controls/Control
 * @require Locale
 * @require css!package/pcsg/gpmauthsecondpassword/bin/controls/Registration.css
 *
 * @event onSubmit
 */
define('package/pcsg/gpmauthsecondpassword/bin/controls/Registration', [

    'qui/controls/Control',
    'qui/controls/buttons/Button',

    'Locale',
    'package/pcsg/grouppasswordmanager/bin/Passwords',

    'css!package/pcsg/gpmauthsecondpassword/bin/controls/Registration.css'

], function (QUIControl, QUIButton, QUILocale, Passwords) {
    "use strict";

    var lg = 'pcsg/gpmauthsecondpassword';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/pcsg/gpmauthsecondpassword/bin/controls/Registration',

        Binds: [
            '$onInject',
            'getAuthData'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$Categories = null;

            this.$Input      = null;
            this.$InputCheck = null;
            this.$show       = false;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * create the domnode element
         *
         * @return {HTMLDivElement}
         */
        create: function () {
            this.parent();

            var self = this;

            this.$Elm.addClass('gpm-auth-second-password');

            this.$Elm.set(
                'html',
                '<label>' +
                '<span class="gpm-auth-second-password-title">' +
                QUILocale.get(lg, 'registration.password.label') +
                '</span>' +
                '<input type="password" class="gpm-auth-second-password-input"/>' +
                '</label>' +
                '<label>' +
                '<span class="gpm-auth-second-password-title">' +
                QUILocale.get(lg, 'registration.passwordcheck.label') +
                '</span>' +
                '<input type="password" class="gpm-auth-second-passwordcheck-input"/>' +
                '</label>' +
                '<div class="gpm-auth-second-password-show">' +
                '<label>' +
                '<span>' +
                QUILocale.get(lg, 'registration.passwordshow.label') +
                '</span>' +
                '<input type="checkbox"/>' +
                '</label>' +
                '</div>' +
                '<div class="gpm-auth-second-password-generate"></div>'
            );

            this.$Input           = this.$Elm.getElement('.gpm-auth-second-password-input');
            this.$InputCheck      = this.$Elm.getElement('.gpm-auth-second-passwordcheck-input');
            var ShowPasswordInput = this.$Elm.getElement('.gpm-auth-second-password-show input');

            ShowPasswordInput.addEvents({
                change: function (event) {
                    var Elm = event.target;

                    if (Elm.checked) {
                        self.$Input.setProperty('type', 'text');
                        self.$InputCheck.setProperty('type', 'text');
                    } else {
                        self.$Input.setProperty('type', 'password');
                        self.$InputCheck.setProperty('type', 'password');
                    }
                }
            });

            this.$Input.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });

            this.$InputCheck.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });

            new QUIButton({
                text     : QUILocale.get(lg, 'registration.random.btn.text'),
                textimage: 'fa fa-random',
                events   : {
                    onClick: function () {
                        if (!ShowPasswordInput.checked) {
                            ShowPasswordInput.click();
                        }

                        Passwords.generateRandomPassword().then(function(randomPass) {
                            self.$Input.value      = randomPass;
                            self.$InputCheck.value = randomPass;
                        });
                    }
                }
            }).inject(
                this.$Elm.getElement('.gpm-auth-second-password-generate')
            );

            return this.$Elm;
        },

        /**
         * event : on inject
         */
        $onInject: function () {
            this.$Input.focus();
        },

        /**
         * Return authentication information
         *
         * @return {object}
         */
        getRegistrationData: function () {
            return JSON.encode({
                password     : this.$Input.value,
                passwordcheck: this.$InputCheck.value
            });
        }
    });
});
