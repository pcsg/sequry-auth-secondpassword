/**
 * Control for creating a new password
 *
 * @module package/sequry/auth-secondpassword/bin/controls/Registration
 * @author www.pcsg.de (Patrick Müller)
 *
 * @event onSubmit
 */
define('package/sequry/auth-secondpassword/bin/controls/Registration', [

    'package/sequry/core/bin/controls/authPlugins/Registration',
    'qui/controls/buttons/Button',

    'Locale',
    'Mustache',

    'package/sequry/core/bin/Passwords',

    'text!package/sequry/auth-secondpassword/bin/controls/Registration.html',
    'css!package/sequry/auth-secondpassword/bin/controls/Registration.css'

], function (RegistrationBaseClass, QUIButton, QUILocale, Mustache, Passwords, template) {
    "use strict";

    var lg = 'sequry/auth-secondpassword';

    return new Class({

        Extends: RegistrationBaseClass,
        Type   : 'package/sequry/auth-secondpassword/bin/controls/Registration',

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
         * event : on inject
         */
        $onInject: function () {
            var self     = this;
            var lgPrefix = 'controls.Registration.template.';

            var Content = new Element('div', {
                'class': 'sequry-auth-secondpassword-registration',
                html   : Mustache.render(template, {
                    labelPassword     : QUILocale.get(lg, lgPrefix + 'labelPassword'),
                    labelPasswordCheck: QUILocale.get(lg, lgPrefix + 'labelPasswordCheck'),
                    labelShowPasswords: QUILocale.get(lg, lgPrefix + 'labelShowPasswords')
                })
            }).inject(this.$Elm);

            this.$Input           = Content.getElement('.sequry-auth-secondpassword-registration-input');
            this.$InputCheck      = Content.getElement('.sequry-auth-secondpassword-registration-inputcheck');
            var ShowPasswordInput = Content.getElement('.sequry-auth-secondpassword-registration-show input');

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
                text     : QUILocale.get(lg, 'controls.Registration.btn_random.text'),
                textimage: 'fa fa-random',
                events   : {
                    onClick: function () {
                        if (!ShowPasswordInput.checked) {
                            ShowPasswordInput.click();
                        }

                        Passwords.generateRandomPassword().then(function (randomPass) {
                            self.$Input.value      = randomPass;
                            self.$InputCheck.value = randomPass;
                        });
                    }
                }
            }).inject(
                this.$Elm.getElement('.sequry-auth-secondpassword-registration-generate')
            );
        },

        /**
         * Focus the element for authentication data input
         */
        focus: function () {
            this.$Input.focus();
        },

        /**
         * Return authentication information
         *
         * @return {string}
         */
        getAuthData: function () {
            return JSON.encode({
                password     : this.$Input.value,
                passwordcheck: this.$InputCheck.value
            });
        }
    });
});
