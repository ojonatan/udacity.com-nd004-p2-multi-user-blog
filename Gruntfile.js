module.exports = function(grunt){
	require('load-grunt-tasks')(grunt);

	grunt.initConfig({
		pkg: grunt.file.readJSON('package.json'),
		watch: {
			less: {
				files:[
					'src/less/**'
				],
				tasks:['less']
			}
		},
		copy: {
			dev: {
				files: [{
					expand: true,
					flatten: true,
					src: 'images_src/prepared/*.{gif,jpg,png,svg}',
					dest: 'public/img'
				}]
			},
		},
		responsive_images: {
			dev: {
				options: {
					engine: 'im',
					sizes: [
						{
							name: 'small',
							width: 320
						},
						{
							name: 'small_2x',
							width: 640
						},
						{
							name: 'medium',
							width: 768
						},
						{
							name: 'medium_2x',
							width: 1560
						},
						{
							name: "large",
							width: 1024,
							separator: "-",
							quality: 60
						},
						{
							name: "large",
							width: 2048,
							separator: "-",
							suffix: "_2x",
							quality: 60
						}
					]
				},

				/*
				You don't need to change this part if you don't change
				the directory structure.
				*/
				files: [{
					expand: true,
					src: ['*.{jpg,png}'],
					cwd: 'images_src/',
					dest: 'images_responsive/'
				}]
			}
		},

		/* Clear out the images directory if it exists */
		clean: {
			dev: {
				src: ['public/img/*'],
			}
		},
		mkdir: {
			dev: {
				options: {
					create: ['public/img']
				},
			},
		},
		less: {
			production: {
				options: {
					sourceMap: false,

					paths: ['public/css'],
					plugins: [
						new (require('less-plugin-autoprefix'))({browsers: ["last 2 versions"]}),
						new (require('less-plugin-clean-css'))({})
					]
				},
				files: {
					'public/css/bootstrap.wrapper.css': 'src/less/bootstrap.wrapper.less'
				}
			}
		},
		imagemin: {													// Task
			dynamic: {												 // Another target
				options: {											 // Target options
					optimizationLevel: 3,
					svgoPlugins: [{ removeViewBox: false }],
					use: [require('imagemin-mozjpeg')()]
				},
				files: [{
					expand: true,									// Enable dynamic expansion
					cwd: 'images_responsive/',									 // Src matches are relative to this path
					src: ['**/*.{png,jpg,gif,jpeg}'],	 // Actual patterns to match
					dest: 'public/img/'									// Destination path prefix
				}]
			}
		}
	});
	grunt.registerTask('images',['responsive_images', 'imagemin']);
	grunt.registerTask('default', ['clean', 'mkdir', 'copy', 'watch']);

};

