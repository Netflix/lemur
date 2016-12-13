'use strict';

var gulp = require('gulp'),
  minifycss = require('gulp-minify-css'),
  concat = require('gulp-concat'),
  less = require('gulp-less'),
  gulpif = require('gulp-if'),
  gutil = require('gulp-util'),
  foreach = require('gulp-foreach'),
  path =require('path'),
  merge = require('merge-stream'),
  del = require('del'),
  size = require('gulp-size'),
  plumber = require('gulp-plumber'),
  autoprefixer = require('gulp-autoprefixer'),
  jshint = require('gulp-jshint'),
  inject = require('gulp-inject'),
  cache = require('gulp-cache'),
  ngAnnotate = require('gulp-ng-annotate'),
  csso = require('gulp-csso'),
  useref = require('gulp-useref'),
  filter = require('gulp-filter'),
  rev = require('gulp-rev'),
  revReplace = require('gulp-rev-replace'),
  imagemin = require('gulp-imagemin'),
  minifyHtml = require('gulp-minify-html'),
  bowerFiles = require('main-bower-files'),
  karma = require('karma'),
  replace = require('gulp-replace');

gulp.task('default', ['clean'], function () {
  gulp.start('fonts', 'styles');
});

gulp.task('clean', function (cb) {
  del(['.tmp', 'lemur/static/dist'], cb);
});

gulp.task('test', function (done) {
  new karma.Server({
    configFile: __dirname + '/karma.conf.js',
    singleRun: true
  }, function() {
    done();
  }).start();
});

gulp.task('dev:fonts', function () {
  var fileList = [
    'bower_components/bootstrap/dist/fonts/*',
    'bower_components/fontawesome/fonts/*'
  ];

  return gulp.src(fileList)
    .pipe(gulp.dest('.tmp/fonts'));
});

gulp.task('dev:styles', function () {
  var baseContent = '@import "bower_components/bootstrap/less/bootstrap.less";@import "bower_components/bootswatch/$theme$/variables.less";@import "bower_components/bootswatch/$theme$/bootswatch.less";@import "bower_components/bootstrap/less/utilities.less";';
  var isBootswatchFile = function (file) {

    var suffix = 'bootswatch.less';
    return file.path.indexOf(suffix, file.path.length - suffix.length) !== -1;
  };

  var isBootstrapFile = function (file) {
    var suffix = 'bootstrap-',
      fileName = path.basename(file.path);

    return fileName.indexOf(suffix) === 0;
  };

  var fileList = [
    'bower_components/bootswatch/sandstone/bootswatch.less',
    'bower_components/fontawesome/css/font-awesome.css',
    'bower_components/angular-spinkit/src/angular-spinkit.css',
    'bower_components/angular-chart.js/dist/angular-chart.css',
    'bower_components/angular-loading-bar/src/loading-bar.css',
    'bower_components/angular-ui-switch/angular-ui-switch.css',
    'bower_components/angular-wizard/dist/angular-wizard.css',
    'bower_components/ng-table/dist/ng-table.css',
    'bower_components/angularjs-toaster/toaster.css',
    'bower_components/angular-ui-select/dist/select.css',
    'lemur/static/app/styles/lemur.css'
  ];

  return gulp.src(fileList)
    .pipe(gulpif(isBootswatchFile, foreach(function (stream, file) {
      var themeName = path.basename(path.dirname(file.path)),
        content = replaceAll(baseContent, '$theme$', themeName),
        file2 = string_src('bootstrap-' +  themeName + '.less', content);

      return file2;
    })))
    .pipe(less())
    .pipe(gulpif(isBootstrapFile, foreach(function (stream, file) {
      var fileName = path.basename(file.path),
        themeName = fileName.substring(fileName.indexOf('-') + 1, fileName.indexOf('.'));

      // http://stackoverflow.com/questions/21719833/gulp-how-to-add-src-files-in-the-middle-of-a-pipe
      // https://github.com/gulpjs/gulp/blob/master/docs/recipes/using-multiple-sources-in-one-task.md
      return merge(stream, gulp.src(['.tmp/styles/font-awesome.css', '.tmp/styles/lemur.css']))
        .pipe(concat('style-' + themeName + '.css'));
    })))
    .pipe(plumber())
    .pipe(concat('styles.css'))
    .pipe(minifycss())
    .pipe(autoprefixer('last 1 version'))
    .pipe(gulp.dest('.tmp/styles'))
    .pipe(size());
});

// http://stackoverflow.com/questions/1144783/replacing-all-occurrences-of-a-string-in-javascript
function escapeRegExp(string) {
  return string.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, '\\$1');
}

function replaceAll(string, find, replace) {
  return string.replace(new RegExp(escapeRegExp(find), 'g'), replace);
}

function string_src(filename, string) {
  var src = require('stream').Readable({ objectMode: true });
  src._read = function () {
    this.push(new gutil.File({ cwd: '', base: '', path: filename, contents: new Buffer(string) }));
    this.push(null);
  };
  return src;
}

gulp.task('dev:scripts', function () {
  return gulp.src(['lemur/static/app/angular/**/*.js'])
    .pipe(jshint())
    .pipe(jshint.reporter('jshint-stylish'))
    .pipe(size());
});

gulp.task('build:extras', function () {
  return gulp.src(['lemur/static/app/*.*', '!lemur/static/app/*.html'])
    .pipe(gulp.dest('lemur/static/dist'));
});

function injectHtml(isDev) {
  return gulp.src('lemur/static/app/index.html')
    .pipe(
    inject(gulp.src(bowerFiles({ base: 'app' })), {
      starttag: '<!-- inject:bower:{{ext}} -->',
      addRootSlash: false,
      ignorePath: isDev ? ['lemur/static/app/', '.tmp/'] : null
    })
  )
    .pipe(inject(gulp.src(['lemur/static/app/angular/**/*.js']), {
      starttag: '<!-- inject:{{ext}} -->',
      addRootSlash: false,
      ignorePath: isDev ? ['lemur/static/app/', '.tmp/'] : null
    }))
    .pipe(inject(gulp.src(['.tmp/styles/**/*.css']), {
      starttag: '<!-- inject:{{ext}} -->',
      addRootSlash: false,
      ignorePath: isDev ? ['lemur/static/app/', '.tmp/'] : null
    }))
    .pipe(
    gulpif(!isDev,
      inject(gulp.src('lemur/static/dist/ngviews/ngviews.min.js'), {
        starttag: '<!-- inject:ngviews -->',
        addRootSlash: false
      })
    )
  )
    .pipe(gulp.dest('.tmp/'));
}

gulp.task('dev:inject', ['dev:styles', 'dev:scripts'], function () {
  return injectHtml(true);
});

gulp.task('build:inject', ['dev:styles', 'dev:scripts', 'build:ngviews'], function () {
  return injectHtml(false);
});

gulp.task('build:ngviews', function () {
  return gulp.src(['lemur/static/app/angular/**/*.html'])
    .pipe(minifyHtml({
      empty: true,
      spare: true,
      quotes: true
    }))
    .pipe(gulp.dest('lemur/static/dist/angular'))
    .pipe(size());
});

gulp.task('build:html', ['dev:styles', 'dev:scripts', 'build:ngviews', 'build:inject'], function () {
  var jsFilter = filter('**/*.js');
  var cssFilter = filter('**/*.css');

  return gulp.src('.tmp/index.html')
    .pipe(rev())
    .pipe(jsFilter)
    .pipe(ngAnnotate())
    .pipe(cssFilter)
    .pipe(csso())
    .pipe(useref())
    .pipe(revReplace())
    .pipe(gulp.dest('lemur/static/dist'))
    .pipe(size());
});

gulp.task('build:fonts', ['dev:fonts'], function () {
  return gulp.src('.tmp/fonts/**/*')
    .pipe(gulp.dest('lemur/static/dist/fonts'));
});

gulp.task('build:images', function () {
  return gulp.src('lemur/static/app/images/**/*')
    .pipe(cache(imagemin({
      optimizationLevel: 3,
      progressive: true,
      interlaced: true
    })))
    .pipe(gulp.dest('lemur/static/dist/images'))
    .pipe(size());
});

gulp.task('package:strip', function () {
  return gulp.src(['lemur/static/dist/scripts/main*'])
    .pipe(replace('http:\/\/localhost:3000', ''))
    .pipe(replace('http:\/\/localhost:8000', ''))
    .pipe(useref())
    .pipe(revReplace())
    .pipe(gulp.dest('lemur/static/dist/scripts'))
    .pipe(size());
});

gulp.task('build', ['build:ngviews', 'build:inject', 'build:images', 'build:fonts', 'build:html', 'build:extras']);
gulp.task('package', ['package:strip']);
