jQuery(function($){
	$('.dropdown-toggle').hoverIntent({
		over: function(){
			if(!$(this).parent('.dropdown').hasClass('open')){
				$(this).dropdown('toggle').focus();
			}
		},
		out: function(e){
			if(!$(e.relatedTarget).hasClass('dropdown-menu')){
				if($(this).parent('.dropdown').hasClass('open')){
					$(this).dropdown('toggle').blur();
				}
			}
		},
		timeout: 100,
	});
	$('.dropdown-menu').hoverIntent({
		out: function(e){
			if(!$(e.relatedTarget).hasClass('dropdown-toggle')){
				if($(this).parent('.dropdown').hasClass('open')){
					$(this).prev('.dropdown-toggle').dropdown('toggle').blur();
				}
			}
		},
		timeout: 100,
	});
});
