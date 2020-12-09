'use strict';

var gulp = require('gulp');

var browserSync = require('browser-sync');
var httpProxy = require('http-proxy');

/* This configuration allow you to configure browser sync to proxy your backend */

 var proxyTarget = 'http://localhost:8000/'; // The location of your backend
 var proxyApiPrefix = '/api/'; // The element in the URL which differentiate between API request and static file request
 var proxy = httpProxy.createProxyServer({
     target: proxyTarget
 });
 function proxyMiddleware(req, res, next) {
     if (req.url.indexOf(proxyApiPrefix) !== -1) {
         proxy.web(req, res);
     } else {
         next();
     }
 }

function browserSyncInit(baseDir, files, browser) {
  browser = browser === undefined ? 'default' : browser;

  browserSync.instance = browserSync.init(files, {
    startPath: '/index.html',
      server: {
          middleware: [proxyMiddleware],
          baseDir: baseDir,
          routes: {
              '/bower_components': './bower_components'
          }
    },
    browser: browser,
    ghostMode: false
  });

}

gulp.task('watch', gulp.series(['dev:styles', 'dev:scripts', 'dev:inject', 'dev:fonts'], function (done) {
  gulp.watch('app/styles/**/*.less', gulp.parallel('dev:styles'));
  gulp.watch('app/styles/**/*.css', gulp.parallel('dev:styles'));
  gulp.watch('app/**/*.js', gulp.parallel('dev:scripts'));
  gulp.watch('app/images/**/*', gulp.parallel('build:images'));
  gulp.watch('bower.json', gulp.parallel('dev:inject'));
  done();
}));

gulp.task('serve', gulp.series('watch', function () {
  browserSyncInit([
    '.tmp',
    'lemur/static/app'
  ], [
    '.tmp/*.html',
    '.tmp/styles/**/*.css',
    'lemur/static/app/angular/**/*.js',
    'lemur/static/app/partials/**/*.html',
    'lemur/static/app/images/**/*',
    'lemur/static/app/angular/**/*',
    'lemur/static/app/index.html'
  ]);
}));


gulp.task('serve:dist', gulp.series('build', function () {
  browserSyncInit('lemur/static/dist');
}));
