// Contents of: config/karma.conf.js
'use strict';

module.exports = function (config) {
    config.set({
        basePath: '../',

        // Fix for "JASMINE is not supported anymore" warning
        frameworks: ['jasmine'],

        files: [
            'app/lib/angular/angular.js',
            'app/lib/angular/angular-*.js',
            'test/lib/angular/angular-mocks.js',
            'app/js/**/*.js',
            'test/unit/**/*.js'
        ],

        autoWatch: true,

        browsers: [process.env.TRAVIS ? 'Chrome_travis_ci' : 'Chrome'],
        customLaunchers: {
            'Chrome_travis_ci': {
                base: 'Chrome',
                flags: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu',],
            },
        },

        junitReporter: {
            outputFile: 'test_out/unit.xml',
            suite: 'unit'
            //...
        },

        failOnEmptyTestSuite: false,
    });
};