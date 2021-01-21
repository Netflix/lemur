'use strict';

var gulp = require('gulp');


const watch = gulp.task('watch', gulp.series(['dev:inject', 'dev:fonts'] ,function (done) {
  gulp.watch('app/styles/**/*.less', gulp.series('dev:styles'));
  gulp.watch('app/styles/**/*.css', gulp.series('dev:styles'));
  gulp.watch('app/**/*.js', gulp.series('dev:scripts'));
  gulp.watch('app/images/**/*', gulp.series('build:images'));
  gulp.watch('bower.json', gulp.series('dev:inject'));
  done();
}));

module.exports = {watch:watch}
