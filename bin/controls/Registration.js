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
    'Locale',

    'css!package/pcsg/gpmauthsecondpassword/bin/controls/Registration.css'

], function (QUIControl, QUILocale) {
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
            this.$Elm = this.parent();

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
                '</label>'
            );

            return this.$Elm;
        },

        /**
         * event : on inject
         */
        $onInject: function () {
            var self       = this;
            var Input      = this.$Elm.getElement('.gpm-auth-second-password-input');
            var InputCheck = this.$Elm.getElement('.gpm-auth-second-passwordcheck-input');

            Input.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });

            InputCheck.addEvents({
                keydown: function (event) {
                    if (typeof event !== 'undefined' &&
                        event.code === 13) {
                        self.fireEvent('submit');
                    }
                }
            });

            Input.focus();
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getRegistrationData: function () {
            return {
                password     : this.$Elm.getElement('.gpm-auth-second-password-input').value,
                passwordcheck: this.$Elm.getElement('.gpm-auth-second-passwordcheck-input').value
            }
        }
    });
});
