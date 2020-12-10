'use strict';

var gulp = require('gulp');


gulp.task('watch', ['dev:styles', 'dev:scripts', 'dev:inject', 'dev:fonts'] ,function () {
  gulp.watch('app/styles/**/*.less', ['dev:styles']);
  gulp.watch('app/styles/**/*.css', ['dev:styles']);
  gulp.watch('app/**/*.js', ['dev:scripts']);
  gulp.watch('app/images/**/*', ['build:images']);
  gulp.watch('bower.json', ['dev:inject']);
});
