'use strict';

var gulp = require('gulp'),
  cleanCSS = require('gulp-clean-css'),
  concat = require('gulp-concat'),
  less = require('gulp-less'),
  gulpif = require('gulp-if'),
  gutil = require('gulp-util'),
  foreach = require('gulp-foreach'),
  path = require('path'),
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
  imagemin = require('gulp-imagemin'),
  minifyHtml = require('gulp-minify-html'),
  bowerFiles = require('main-bower-files'),
  karma = require('karma'),
  replace = require('gulp-replace'),
  argv = require('yargs').argv;

// http://stackoverflow.com/questions/1144783/replacing-all-occurrences-of-a-string-in-javascript
function escapeRegExp(string) {
  return string.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, '\\$1');
}

function replaceAll(string, find, replace) {
  return string.replace(new RegExp(escapeRegExp(find), 'g'), replace);
}

function stringSrc(filename, string) {
  let src = require('stream').Readable({objectMode: true});
  src._read = function () {
    this.push(new gutil.File({cwd: '', base: '', path: filename, contents: Buffer.from(string)}));
    this.push(null);
  };
  return src;
}

gulp.task('clean', function (done) {
  del(['.tmp', 'lemur/static/dist'], done);
  done();
});

gulp.task('default', gulp.series(['clean'], function () {
  gulp.start('fonts', 'styles');
}));

gulp.task('test', function (done) {
  new karma.Server({
    configFile: __dirname + '/karma.conf.js',
    singleRun: true
  }, function (err) {
    if (err === 0) {
      done();
    } else {
      // if karma server failed to start raise error
      done(new gutil.PluginError('karma', {
        message: 'Karma Tests failed'
      }));
    }
  }).start();
});

gulp.task('dev:fonts', function () {
  let fileList = [
    'bower_components/bootstrap/dist/fonts/*',
    'bower_components/fontawesome/fonts/*'
  ];

  return gulp.src(fileList)
    .pipe(gulp.dest('.tmp/fonts')); // returns a stream making it async
});

gulp.task('dev:styles', function () {
  let baseContent = '@import "bower_components/bootstrap/less/bootstrap.less";@import "bower_components/bootswatch/$theme$/variables.less";@import "bower_components/bootswatch/$theme$/bootswatch.less";@import "bower_components/bootstrap/less/utilities.less";';
  let isBootswatchFile = function (file) {

    let suffix = 'bootswatch.less';
    return file.path.indexOf(suffix, file.path.length - suffix.length) !== -1;
  };

  let isBootstrapFile = function (file) {
    let suffix = 'bootstrap-',
      fileName = path.basename(file.path);

    return fileName.indexOf(suffix) === 0;
  };

  let fileList = [
    'bower_components/bootswatch/sandstone/bootswatch.less',
    'bower_components/fontawesome/css/font-awesome.css',
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
      let themeName = path.basename(path.dirname(file.path)),
        content = replaceAll(baseContent, '$theme$', themeName);
      return stringSrc('bootstrap-' + themeName + '.less', content);
    })))
    .pipe(less())
    .pipe(gulpif(isBootstrapFile, foreach(function (stream, file) {
      let fileName = path.basename(file.path),
        themeName = fileName.substring(fileName.indexOf('-') + 1, fileName.indexOf('.'));

      // http://stackoverflow.com/questions/21719833/gulp-how-to-add-src-files-in-the-middle-of-a-pipe
      // https://github.com/gulpjs/gulp/blob/master/docs/recipes/using-multiple-sources-in-one-task.md
      return merge(stream, gulp.src(['.tmp/styles/font-awesome.css', '.tmp/styles/lemur.css'], {allowEmpty: true}))
        .pipe(concat('style-' + themeName + '.css'));
    })))
    .pipe(plumber())
    .pipe(concat('styles.css'))
    .pipe(cleanCSS())
    .pipe(autoprefixer('last 1 version'))
    .pipe(gulp.dest('.tmp/styles'))
    .pipe(size());
});

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
      inject(gulp.src(bowerFiles({base: 'app'})), {
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
        inject(gulp.src('lemur/static/dist/ngviews/ngviews.min.js', {allowEmpty: true}), {
          starttag: '<!-- inject:ngviews -->',
          addRootSlash: false
        })
      )
    ).pipe(gulp.dest('.tmp/'));
}

gulp.task('dev:inject', gulp.series(['dev:styles', 'dev:scripts'], function () {
  return injectHtml(true);
}));

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

gulp.task('build:inject', gulp.series(['dev:styles', 'dev:scripts', 'build:ngviews'], function () {
  return injectHtml(false);
}));

gulp.task('build:html', gulp.series(['build:inject'], function () {
  let jsFilter = filter(['**/*.js'], {'restore': true});
  let cssFilter = filter(['**/*.css'], {'restore': true});

  return gulp.src('.tmp/index.html')
    .pipe(jsFilter)
    .pipe(ngAnnotate())
    .pipe(jsFilter.restore)
    .pipe(cssFilter)
    .pipe(csso())
    .pipe(cssFilter.restore)
    .pipe(useref())
    .pipe(gulp.dest('lemur/static/dist'))
    .pipe(size());
}));

gulp.task('build:fonts', gulp.series(['dev:fonts'], function () {
  return gulp.src('.tmp/fonts/**/*')
    .pipe(gulp.dest('lemur/static/dist/fonts'));
}));

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
    .pipe(gulp.dest('lemur/static/dist/scripts'))
    .pipe(size());
});

gulp.task('addUrlContextPath:revision', function () {
  return gulp.src(['lemur/static/dist/**/*.css', 'lemur/static/dist/**/*.js'])
    .pipe(rev())
    .pipe(gulp.dest('lemur/static/dist'))
    .pipe(rev.manifest())
    .pipe(gulp.dest('lemur/static/dist'));
});

gulp.task('addUrlContextPath:revreplace', gulp.series(['addUrlContextPath:revision'], function () {
  return gulp.src('lemur/static/dist/index.html')
    .pipe(gulp.dest('lemur/static/dist'));
}));

gulp.task('addUrlContextPath', gulp.series(['addUrlContextPath:revreplace'], function () {
  let urlContextPathExists = !!argv.urlContextPath;
  return gulp.src(['lemur/static/dist/scripts/main*.js', 'lemur/static/dist/angular/**/*.html'])
    .pipe(gulpif(urlContextPathExists, replace('api/', argv.urlContextPath + '/api/')))
    .pipe(gulpif(urlContextPathExists, replace('/angular/', '/' + argv.urlContextPath + '/angular/')))
    .pipe(gulp.dest(function (file) {
      return file.base;
    }));
}));

gulp.task('build', gulp.series(['build:images', 'build:fonts', 'build:html', 'build:extras']));
gulp.task('package', gulp.series(['addUrlContextPath', 'package:strip']));
