/**
 * Created by kglisson on 1/19/15.
 */
'use strict';

var gulp = require('gulp');

require('require-dir')('./gulp');

gulp.task('default', function () {
  var c = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    magenta: '\x1b[35m'
  };

  console.log('');
  console.log(c.green + c.bold + 'Main Commands' + c.reset);
  console.log(c.green + '-------------------------------------------' + c.reset);
  console.log(c.green + 'clean' + c.reset + ' - delete the .tmp/ and dist/ folders.');
  console.log(c.green + 'build' + c.reset + ' - execute the release build and output into the dist/ folder.');
  console.log(c.green + 'serve:dist' + c.reset + ' - execute the release build and output into the dist/ folder then run a local server for the files.');
  console.log(c.green + 'serve' + c.reset + ' - run JShint and LESS compiler to produce .tmp/ folder. Then serve up the app on a local server.');
  console.log('');
  console.log(c.green + c.bold + 'All Commands' + c.reset);
  console.log(c.green + '-------------------------------------------' + c.reset);
  console.log(Object.keys(gulp.tasks).sort().join('\n'));
  console.log('');

});
