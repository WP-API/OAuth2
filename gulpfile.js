const gulp = require( 'gulp' ),
	shell = require( 'gulp-shell' ),
	guppy = require( 'git-guppy' )( gulp );

gulp.task( 'phpcs', shell.task( [ 'npm run-script phpcs' ] ) );
gulp.task( 'pre-commit', [ 'phpcs' ] );
