$.fn.center = function () {
	var w = $(window);
	this.css("position", "absolute");
	this.css("top", (w.height() - this.height())/2 + w.scrollTop() + "px");
	this.css("left", (w.width() - this.width())/2 + w.scrollLeft() + "px");
	return this;
}

function popup(o) {
	var closebutton = $("<a class='popup ui-helper-hidden-accessible popupbutton ui-state-default ui-corner-all' style='padding-left:14px;position:absolute;' href='javascript:endpopup()'><span class='ui-icon ui-icon-close' ></span>&nbsp;</a>");
	o = $("<div class='ui-widget ui-widget-content ui-corner-all' style='opacity:1'></div>").html(o);
	o.addClass("ui-helper-hidden-accessible popup");
	o.css({
		"min-width": 300,
		"max-width": $(window).width()-100,
		"max-height": $(window).height() - 100,
		"overflow":"auto",
	});
	
	var p = $("<div class='popup ui-widget-shadow ui-corner-all ui-helper-hidden-accessible'></div>");
	$('body').append("<div class='popup ui-widget-overlay'></div>").append(p).append(o).append(closebutton);
	

	o.center().removeClass("ui-helper-hidden-accessible");
	p.width(o.width());
	p.height(o.height());
	p.center().removeClass("ui-helper-hidden-accessible");
	closebutton.removeClass("ui-helper-hidden-accessible");
	var pos = p.offset();
	closebutton.css({
		'left':pos.left + p.width() - closebutton.width()-15,
		'top':pos.top - closebutton.height(),
	});
	fixbuttons('.popupbutton');
}
function endpopup() {
	$('.popup').remove();
}


function test_ip(ip) {
	var r = /^\d+\.\d+\.\d+\.\d+$/;
	if (r.test(ip)) {
		var o = ip.split(".")
		for(var i = 0; i < 4; i++) {
			var octet = parseInt(o[i]);
			if (octet < 0 || octet > 255) {
				return False;
			}
		}
		return true;			
	}
	return false;
}

function test_port(port) {
	var r = /^\d{1,5}/;
	if (r.test(port)) {
		var p = parseInt(port)
		if (p >= 0 && p <= 65535) {
			return true;
		}
	}
	return false;
}

function ip_input(id) {
	if (id) {
		id = "id='"+id+"'";
	} 
	return $("<input type='text' "+id+"></input>").blur(function() {
		if (!test_ip($(this).val())) {
			warn($(this).val() +" is a bad IP address");
		}
	});
}

function port_input(id) {
	if (id) {
		id = "id='"+id+"'";
	} 
	return $("<input type='text' "+id+"></input>").blur(function() {
		if (!test_port($(this).val())) {
			warn($(this).val() +" is a bad IP port");
		}
	});
}

function log(txt) {
	$('#Notification').jnotifyAddMessage({
		text:txt,
		permanent:false
	});
}
function warn(txt) {
	$('#Notification').jnotifyAddMessage({
		text:txt,
		permanent:false,
		type:'error',
	});
}
function debug(txt) {
	log(txt);
}

function fixbuttons(o) {
	$(o).hover(
		function() { $(this).addClass('ui-state-hover');},
		function() { $(this).removeClass('ui-state-hover');}
	);
}

$(document).ready(function() {
	$('body').prepend("<div id='Notification'></div>");
	$('#Notification').jnotifyInizialize({
		oneAtTime: false,
		appendType: 'append',
	}).css({
		'position':'absolute',
		'marginTop': '20px',
		'right':'20px',
		'width':'400px',
		'z-index':'9999'
	});
	$('a.verify').click(function(e) {
		e.preventDefault();
		popup("<div style='padding:15px;text-align:center;'><div style='font-size:120%;font-weight:bold;padding-bottom:15px;'>Are you sure?</div><a class='ui-state-default ui-corner-all' href='"+$(this).attr('href')+"'><span class='ui-icon ui-icon-check'></span>Yes</a>&nbsp;&nbsp<a class='ui-state-default ui-corner-all' href='javascript:endpopup()'><span class='ui-icon ui-icon-close'></span>No</a></div>");
		fixbuttons('.popup a');

	});
	$('a.aspopup').click(function(e) {
		e.preventDefault();
		$.ajax({
			url:$(this).attr('href'),
			success:function(data) {
				popup(data);
			}
		});
	});
	fixbuttons('a.ui-state-default');
});

