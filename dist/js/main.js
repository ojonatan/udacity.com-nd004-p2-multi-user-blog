function equalize_height(c_ITEMS) {

	var i_tallest = 0;
	var c_stack = [];

	var b_single = ($('article').get(0).clientWidth == $('article').first().parent().get(0).clientWidth);
	c_ITEMS.each(function(i,article) {
		$(article).height("auto");
		if($(article).outerHeight(true) > i_tallest) {
			i_tallest = $(article).outerHeight(true);
		}
	});
	c_ITEMS.height(
		!b_single ?
			i_tallest
			:
			"auto"
	);

}

$(document).ready(function(){
	if($('#post-form').length){
		return initBlogForm();
	}

	if($('article.post').length){
		return initBlogMain();
	}
});

function initBlogForm(){
	upload_urls = []
	$('#post-form').on(
		'submit',
		function(){
			if($(this).data('ready') > 0){
				if(tinymce.activeEditor.getContent().indexOf('src="data:') > -1){
					alert("Please wait until all modified images are saved..");
					return false;
				}
				tinymce.activeEditor.setMode('readonly');
				return true;
			}
			$('.fileinput-upload').trigger('click');
			$(this).data('ready','2')
			return false;
		}
	);

	function refresh_upload_url(){
		console.log("REFRESHING UPLOAD URL.....");
		json = $.parseJSON(
			$.ajax({
				url: $('.form-control-upload').first().data("blog-upload-url-source"),
				async: false,
				dataType: "json"
			}).responseText
		);
		return json.upload_url;
	}

    (function() {
		var proxied = window.XMLHttpRequest.prototype.open;
		window.XMLHttpRequest.prototype.open = function() {
			try
			{
				if(arguments[1].indexOf('/_ah/upload/') > -1){
					arguments[1] = refresh_upload_url()
					console.log('FORCE REFRESH UPLOAD URL TO ' + arguments[1])
				}
			} catch(e){

			}
			return proxied.apply(this, [].slice.call(arguments));
		};
	})();

	var file_input_options = {
		'uploadUrl': $('.form-control-upload').first().data("blog-upload-url"),
		'minFileCount': 0,
		'maxFileCount': 1,
		'uploadAsync': true,
	};

	if($('#post-cover-url').val()){
		file_input_options.initialPreview = [
			'<img src="' + $('#post-cover-url').val() + '" class="file-preview-image" alt="Post Cover" title="Post Cover">',
		];
	}

	$("#post-cover").fileinput(file_input_options);
	$('#post-cover').on('fileselect', function(event, data, previewId, index, jqXHR) {
		console.log("File selected. Blocking form until upload complete.");
		$('#post-form').data("ready","0");
	});

	$('#post-cover').on('fileuploaded', function(event, data, previewId, index, jqXHR) {
		console.log("File uploaded. Form will be submitted");
		$('#post-cover-url').val(data.jqXHR.responseJSON.location);
		if($('#post-form').data("ready") == 2){
			console.log("Submitting, the form.");
			$('#post-form').submit();
		} else {
			console.log("Uoploading ahead.");
			$('#post-form').data("ready","1");
		}
	});

	$('#post-cover').on('fileclear', function(event) {
		console.log("Clearing image");
		$('#post-cover-url').val("");
		return true;
	});

	tinymce.init(
		{
			selector: '#content',
			height: 500,
			theme: 'modern',
			plugins: [
				'advlist autolink lists image charmap print preview hr pagebreak',
				'searchreplace wordcount visualblocks visualchars code fullscreen',
				'insertdatetime nonbreaking save table contextmenu',
				'emoticons template paste textcolor colorpicker textpattern imagetools codesample toc'
			],
			images_upload_url: $('.form-control-upload').first().data("blog-upload-url"),
			automatic_uploads: true,
			file_picker_types: 'image',
			file_picker_callback: function(cb, value, meta) {
				var input = document.createElement('input');
				input.setAttribute('type', 'file');
				input.setAttribute('accept', 'image/*');
				input.onchange = function() {
					var file = this.files[0];
					var id = 'blobid' + (new Date()).getTime();
					var blobCache = tinymce.activeEditor.editorUpload.blobCache;
					var blobInfo = blobCache.create(id, file);
					blobCache.add(blobInfo);
					cb(
						blobInfo.blobUri(),
						{
							title: file.name
						}
					);
				};
				input.click();
			},
			toolbar1: 'undo redo | insert | styleselect | bold italic | bullist numlist outdent indent | link image',
			toolbar2: 'preview media | forecolor backcolor emoticons | codesample',
			image_advtab: true,
			invalid_elements: "h1,h2",
			style_formats: [
				{
					title: 'Headers',
					items: [
						{
							title:'Header 3',
							format:'h3'
						},
						{
							title:'Header 4',
							format:'h4'
						},
						{
							title:'Header 5',
							format:'h5'
						},
						{
							title:'Header 6',
							format:'h6'
						}
					]
				},
				{
					title: 'Inline',
					items: [
						{
							title:'Bold',
							icon:'bold',
							format:'bold'
						},
						{
							title:'Italic',
							icon:'italic',
							format:'italic'
						},
						{
							title:'Underline',
							icon:'underline',
							format:'underline'
						},
						{
							title:'Strikethrough',
							icon:'strikethrough',
							format:'strikethrough'
						},
						{
							title:'Superscript',
							icon:'superscript',
							format:'superscript'
						},
						{
							title:'Subscript',
							icon:'subscript',
							format:'subscript'
						},
						{
							title:'Code',
							icon:'code',
							format:'code'
						}
					]
				},
				{
					title:'Blocks',
					items: [
						{
							title:'Paragraph',
							format:'p'
						},
						{
							title:'Blockquote',
							format:'blockquote'
						},
						{
							title:'Div',
							format:'div'
						},
						{
							title:'Pre',
							format:'pre'
						}
					]
				},
				{
					title: 'Alignment',
					items: [
						{
							title:'Left',
							icon:'alignleft',
							format:'alignleft'
						},
						{
							title:'Center',
							icon:'aligncenter',
							format:'aligncenter'
						},
						{
							title:'Right',
							icon:'alignright',
							format:'alignright'
						},
						{
							title:'Justify',
							icon:'alignjustify',
							format:'alignjustify'
						}
					]
				}
			]
		}
	);
}
function initBlogMain(){
	$(window).resize(function(){
		equalize_height($('.post'));
	});
	$(window).resize();
}
