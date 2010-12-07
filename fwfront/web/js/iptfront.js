function docall(obj, func, args, success, failure) {
	//debug(obj+"."+func+"("+args.toString()+")");
	if (typeof(failure) == 'undefined') {
		failure = function(xhr,txt,error) {
			warn("Call to "+obj+"."+func+" failed: "+txt);
		}
	}
	if (typeof(success) == 'undefined') {	
		success = function (o, txt, xhr) {
			if (o.__class__ != "Status") {
				debug("Call to "+obj+"."+func+" returning unhandled object");
			}
		}
	}
				
	var handleret = function(o, txt, xhr) {
		o = o[0];
		if (o.__class__ == "Status") {
			if (o.t == "Success") {
				debug("Call to "+obj+"."+func+" Succeeded: "+o.s);
				success(o, o.t, xhr);
			} else if (o.t == "Error") {
				failure(xhr, o.s);
			} else {
				log("Call to "+obj+".".func+" returned "+o.t+":"+o.s);
			}
		} else {
			debug("Call to "+obj+"."+func+" Succeeded, "+o.__class__+" returned");
			success(o, txt, xhr);
		}
	}
	$.ajax({
		url:"/data/"+obj,
		data:JSON.stringify({
			action:func,
			args:args,
		}),
		dataType:"json",
		error:failure,
		success:handleret,
		type:"POST",
	});
}

$.fn.center = function () {
	var w = $(window);
	this.css("position", "absolute");
	this.css("top", (w.height() - this.height())/2 + w.scrollTop() + "px");
	this.css("left", (w.width() - this.width())/2 + w.scrollLeft() + "px");
	return this;
}

var ops = {
	opslist:[],
	opspos:0,
	opslen:0,
	add:function(undo, redo, description) {
		this.opslist[this.opspos] = [undo, redo, description];
		this.opspos += 1;
		this.opslen == this.opspos;
	},
	canundo: function() {
		return this.opspos > 0;
	},
	undo:function() {
		if (this.canundo()) {
			this.opspos -= 1;
			this.opslist[this.opspos][0]();
		} else {
			warn("Reached bottom of undo history, no more undo's left.");
		}
	},
	canredo:function() {
		return this.opspos < opslen;
	},
	redo:function() {
		if (this.canredo()) {
			this.opslist[this.opspos][1]();
			this.opspos += 1;
		} else {
			warn("Reached most recent change. No more redo's possible.");
		}
	}
}

function popup(o) {
	o = $("<div class='ui-widget ui-widget-content ui-corner-all' style='opacity:1;'></div>").html(o);
	o.addClass("ui-helper-hidden-accessble popup");
	o.css("min-width", 300);
	
	var p = $("<div class='popup ui-widget-shadow ui-corner-all ui-helper-hidden-accessible'></div>");
	$('body').append("<div class='popup ui-widget-overlay'></div>").append(p).append(o);

	o.center().removeClass("ui-helper-hidden-accessible");
	p.width(o.width());
	p.height(o.height());
	p.center().removeClass("ui-helper-hidden-accessible");
}
function endpopup() {
	$('.popup').remove();
}

function apitemplate(fname) {
	return $("<i>"+$('#objname').val()+"."+fname+"</i>"+"(<br><textarea id='apiargs' cols=40 rows=10></textarea><br>)<br><button onclick='docall($(\"#objname\").val(),\""+fname+"\",eval($(\"#apiargs\").val()));endpopup()'>Execute</button><button onclick='endpopup()'>Cancel</button>");
}

function addtoset(oname, t, types) {
	var i;
	var inp = "";
	for (i = 0; i < types.length; i++) {
		if (types[i] == 'ip') {
			inp += "<input class='set_inp_ip set_inp' type='text'></input>";
		//} else if (types[i] == 'net') {
		//	inp += "<input class='set_inp_net set_inp' type='text'></input>";
		} else if (types[i] == 'port') {
			inp += "<input class 'set_inp_port set_inp' type='text'></input>";
		}
	}
	var ret = $(inp + "<br><button class='btnadd'>Add</button><button class='btncancel'>Cancel</button>");
	ret.find('.set_inp_ip').blur(function() {
		if (!test_ip($(this).val())) {
			warn($(this).val() + " is not a valid ip address");
		}
	});
	ret.find('.set_inp_port').blur(function() {
		if (!test_ip($(this).val())) {
			warn($(this).val() + " is not a valid port");
		}
	});
	popup(ret);		
	$('button.btnadd').click(function() {
		var row = [];
		var success = true;
		ret.find('.set_inp').each(function() {
			var i = $(this);
			if (i.hasClass("set_inp_ip")) {
				if (!test_ip(i.val())) {
					warn(i.val() + " is not a valid ip address");
					success = false;
				}
			} else if (i.hasClass("set_inp_port")) {
				if (!test_port(i.val())) {
					warn(i.val() + " is not a valid port");
					success = false;
				}
			}
			row.push(i.val());
		});
		if (success) {
			ipset_row_insert(oname, row, t);
			endpopup();
		}
	});
	$('button.btncancel').click(function() {
		endpopup();
	});
	
}

var templates = {
	fallback:function(obj){
		return "<pre>"+JSON.stringify(obj)+"</pre>";
	},
	objDetails:function(obj) {
		var ret = "<h2>" + obj.type + "</h3>"
		if (obj.doc && obj.doc != "") {
			ret += "<pre>"+obj.doc+"</pre>";
		} else {
			ret += "<i>No documentation</i><br>";
		}
		if (obj.methods.length) {
			ret += "<h3>Methods</h3>";
			var i;
			for(i = 0; i < obj.methods.length; i++) {
				ret += "<h5 style='margin-left:10px;cursor:pointer;' onclick='popup(apitemplate(\""+obj.methods[i].method+"\"))'>"+obj.methods[i].method+"</h5>";
				if (obj.methods[i].doc) {
					ret += "<pre>"+obj.methods[i].doc+"</pre>";
				}
			}
		} else {
			ret += "<i>No methods</i><br>";
		}
		return ret;
	},
	IPSet:function(obj) {
		var k;
		var ret = "";
		for (k in obj) {
			if (k != "__class__" && k != "ipset") {
				ret += "<li><strong>"+k+":</strong>"+obj[k]+"</li>";
			}
		}
		ret += "</ul><div class='ui-widget ui-corner-all ui-widget-content'><div class='ui-widget-header'>Items in Set</div><div style='height:300px; overflow:auto;'>";
		ret += "<table>";
		if (obj.settype == "ipmap" || obj.settype == "iphash") {
			ret += "<tr><th class='ui-icon ui-icon-plus' onclick='addtoset(\""+obj.name+"\",$(this).parent(), [\"ip\"])' style='cursor:pointer;'></th><th>IP</th></tr>";
		} else if (obj.settype == "portmap") {
			ret += "<tr><th class='ui-icon ui-icon-plus' onclick='addtoset(\""+obj.name+"\",$(this).parent(), [\"port\"])' style='cursor:pointer;'></th><th>Port</th></tr>";
		} else if (obj.settype == "ipporthash") {
			ret += "<tr><th class='ui-icon ui-icon-plus' onclick='addtoset(\""+obj.name+"\",$(this).parent(), [\"ip\",\"port\"])' style='cursor:pointer;'></th><th>IP</th><th>Port</th></tr>";
		} else if (obj.settype == "ipportiphash") {
			ret += "<tr><th class='ui-icon ui-icon-plus' onclick='addtoset(\""+obj.name+"\",$(this).parent(), [\"ip\",\"port\",\"ip\"])' style='cursor:pointer;'></th><th>IP</th><th>Port</th><th>IP</th></tr>";
		} else {
			return "Not supported";
		}			
		obj.ipset.sort();	
		for (k = 0; k < obj.ipset.length; k++) {
			ret += "<tr>";
			ret += "<td class='ui-icon ui-icon-minus' style='cursor:pointer' onclick='ipset_row_remove(\""+obj.name+"\", $(this).parent())'></td>"
			for(var i = 0; i < obj.ipset[k].length; i++) {
				ret += "<td>"+obj.ipset[k][i]+"</td>";
			}
			ret += "</tr>";
		}
		ret += "</table></div></div>"
		return ret;
	}
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

function ipset_row_remove(o, r) {
	var row = [];
	r.children().each(function() {
		row.push($(this).text());
	});
	docall(o, "remove", row, function() {
		r.animate({opacity:0.0}, function() {
			r.remove();
		});
	});
}
function ipset_row_insert(oname, r, t) {
	var nextrow = null;
	t.find("tr").each(function() {
		var data = [];
		$(this).find("td").each(function () {
			var txt = $(this).text();
			if (txt != "") {
				data.push($(this).text());
			}
		});
		if (data.length) {
			if (r < data) {
				nextrow = $(this);
				return false;
			}			
		}
	});
	var newrow = "<tr><td class='ui-icon ui-icon-minus' style='cursor:pointer' onclick='ipset_row_remove(\""+oname+"\", $(this).parent())'></td>"
	var i;
	for (i = 0; i < r.length; i++) {
		newrow += "<td>"+r[i]+"</td>";
	}
	newrow += "</tr>";
	if (nextrow != null) {
		nextrow.before(newrow);
	} else {
		t.append(newrow);	
	}
}

function formatobj(obj) {
	if (obj.__class__ in templates) {
		return templates[obj.__class__](obj);
	} else {
		return templates.fallback(obj);
	}
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
});

