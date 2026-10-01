const SAI_JS_API_VERSION = 4;

(function() {

/*
 * We display untrusted stuff in html context... reject anything
 * that has HTML stuff in it
 */

/* http://i18njs.com/ this from http://i18njs.com/js/i18n.js */
(function() {
  var Translator, i18n, translator,
    __bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  Translator = (function() {
    function Translator() {
      this.translate = __bind(this.translate, this);      this.data = {
        values: {},
        contexts: []
      };
      this.globalContext = {};
    }

    Translator.prototype.translate = function(text, defaultNumOrFormatting,
			numOrFormattingOrContext, formattingOrContext, context) {
      var defaultText, formatting, isObject, num;

      if (context == null) {
        context = this.globalContext;
      }
      isObject = function(obj) {
        var type;

        type = typeof obj;
        return type === "function" || type === "object" && !!obj;
      };
      if (isObject(defaultNumOrFormatting)) {
        defaultText = null;
        num = null;
        formatting = defaultNumOrFormatting;
        context = numOrFormattingOrContext || this.globalContext;
      } else {
        if (typeof defaultNumOrFormatting === "number") {
          defaultText = null;
          num = defaultNumOrFormatting;
          formatting = numOrFormattingOrContext;
          context = formattingOrContext || this.globalContext;
        } else {
          defaultText = defaultNumOrFormatting;
          if (typeof numOrFormattingOrContext === "number") {
            num = numOrFormattingOrContext;
            formatting = formattingOrContext;
            context = context;
          } else {
            num = null;
            formatting = numOrFormattingOrContext;
            context = formattingOrContext || this.globalContext;
          }
        }
      }
      if (isObject(text)) {
        if (isObject(text['i18n'])) {
          text = text['i18n'];
        }
        return this.translateHash(text, context);
      } else {
        return this.translateText(text, num, formatting, context, defaultText);
      }
    };

    Translator.prototype.add = function(d) {
      var c, v, _i, _len, _ref, _ref1, _results;

      if ((d.values != null)) {
        _ref = d.values;
        var k;
        for (k in _ref) {
	  if ({}.hasOwnProperty.call(_ref, k)) {
          v = _ref[k];
          this.data.values[k] = v;
	  }
        }
      }
      if ((d.contexts != null)) {
        _ref1 = d.contexts;
        _results = [];
        for (_i = 0, _len = _ref1.length; _i < _len; _i++) {
          c = _ref1[_i];
          _results.push(this.data.contexts.push(c));
        }
        return _results;
      }
    };

    Translator.prototype.setContext = function(key, value) {
      return this.globalContext[key] = value;
    };

    Translator.prototype.clearContext = function(key) {
      return this.lobalContext[key] = null;
    };

    Translator.prototype.reset = function() {
      this.data = {
        values: {},
        contexts: []
      };
      return this.globalContext = {};
    };

    Translator.prototype.resetData = function() {
      return this.data = {
        values: {},
        contexts: []
      };
    };

    Translator.prototype.resetContext = function() {
      return this.globalContext = {};
    };

    Translator.prototype.translateHash = function(hash, context) {
      var k, v;

      for (k in hash) {
	  if ({}.hasOwnProperty.call(hash, k)) {
	        v = hash[k];
	        if (typeof v === "string") {
	          hash[k] = this.translateText(v, null, null, context);
	        }
	  }
      }
      return hash;
    };

    Translator.prototype.translateText = function(text, num, formatting,
						context, defaultText) {
      var contextData, result;

      if (context == null) {
        context = this.globalContext;
      }
      if (this.data == null) {
        return this.useOriginalText(defaultText || text, num, formatting);
      }
      contextData = this.getContextData(this.data, context);
      if (contextData != null) {
        result = this.findTranslation(text, num, formatting, contextData.values,
					defaultText);
      }
      if (result == null) {
        result = this.findTranslation(text, num, formatting, this.data.values,
					defaultText);
      }
      if (result == null) {
        return this.useOriginalText(defaultText || text, num, formatting);
      }
      return result;
    };

    Translator.prototype.findTranslation = function(text, num, formatting, data) {
      var result, triple, value, _i, _len;

      value = data[text];
      if (value == null) {
        return null;
      }
      if (num == null) {
        if (typeof value === "string") {
          return this.applyFormatting(value, num, formatting);
        }
      } else {
        if (value instanceof Array || value.length) {
          for (_i = 0, _len = value.length; _i < _len; _i++) {
            triple = value[_i];
            if ((num >= triple[0] || triple[0] === null) &&
                (num <= triple[1] || triple[1] === null)) {
              result = this.applyFormatting(triple[2].replace("-%n",
						String(-num)), num, formatting);
              return this.applyFormatting(result.replace("%n",
						String(num)), num, formatting);
            }
          }
        }
      }
      return null;
    };

    Translator.prototype.getContextData = function(data, context) {
      var c, equal, key, value, _i, _len, _ref, _ref1;

      if (data.contexts == null) {
        return null;
      }
      _ref = data.contexts;
      for (_i = 0, _len = _ref.length; _i < _len; _i++) {
        c = _ref[_i];
        equal = true;
        _ref1 = c.matches;
        for (key in _ref1) {
		if ({}.hasOwnProperty.call(_ref1, key)) {
			value = _ref1[key];
			equal = equal && value === context[key];
		}
        }
        if (equal) {
          return c;
        }
      }
      return null;
    };

    Translator.prototype.useOriginalText = function(text, num, formatting) {
      if (num == null) {
        return this.applyFormatting(text, num, formatting);
      }
      return this.applyFormatting(text.replace("%n", String(num)),
					num, formatting);
    };

    Translator.prototype.applyFormatting = function(text, num, formatting) {
      var ind, regex;

      for (ind in formatting) {
	  if ({}.hasOwnProperty.call(formatting, ind)) {
	        regex = new RegExp("%{" + ind + "}", "g");
	        text = text.replace(regex, formatting[ind]);
	  }
      }
      return text;
    };

    return Translator;

  })();

  translator = new Translator();

  i18n = translator.translate;

  i18n.translator = translator;

  i18n.create = function(data) {
    var trans;

    trans = new Translator();
    if (data != null) {
      trans.add(data);
    }
    trans.translate.create = i18n.create;
    return trans.translate;
  };

  (typeof module !== "undefined" && module !== null ? module.exports = i18n : void 0) ||
	(this.i18n = i18n);

}.call(this));

var lang_ja = "{" +
  "\"values\":{" +
    "\"Summary\": \"概要\"," +
    "\"Log\": \"ログ\"," +
    "\"Tree\": \"木構造\"," +
    "\"Blame\": \"責任\"," +
    "\"Copy Lines\": \"コピーライン\"," +
    "\"Copy Link\": \"リンクをコピーする\"," +
    "\"View Blame\": \"責任がある\"," +
    "\"Remove Blame\": \"責任を取り除く\"," +
    "\"Mode\": \"モード\"," +
    "\"Size\": \"サイズ\"," +
    "\"Name\": \"名\"," +
    "\"s\": \"秒\"," +
    "\"m\": \"分\"," +
    "\"h\": \"時間\"," +
    "\" days\": \"日々\"," +
	"\" weeks\": \"週\"," +
	"\" months\": \"数ヶ月\"," +
	"\" years\": \"年\"," +
	"\"Branch Snapshot\": \"ブランチスナップショット\"," +
	"\"Tag Snapshot\": \"タグスナップショット\"," +
	"\"Commit Snapshot\": \"スナップショットをコミットする\"," +
	"\"Description\": \"説明\"," +
	"\"Owner\": \"オーナー\"," +
	"\"Branch\": \"ブランチ\"," +
	"\"Tag\": \"タグ\"," +
	"\"Author\": \"著者\"," +
	"\"Age\": \"年齢\"," +
	"\"Page fetched\": \"ページを取得した\"," +
	"\"creation time\": \"作成時間\"," +
	"\"created\": \"作成した\"," +
	"\"ago\": \"前\"," +
	"\"Message\": \"メッセージ\"," +
	"\"Download\": \"ダウンロード\"," +
	"\"root\": \"ルート\"," +
	"\"Committer\": \"コミッター\"," +
	"\"Raw Patch\": \"生パッチ\"," +
	"\"Page fetched %{pf} ago, creation time: %{ct}ms " +
	   "(vhost etag hits: %{ve}%, cache hits: %{ch}%)\": " +
	"\"%{pf}間前に取得されたページ, 作成にかかった時間: %{ct}ms " +
	   "(vhost etag キャッシュヒット: %{ve}%, キャッシュヒット: %{ch}%)\"," +
	"\"Created %{pf} ago, creation time: %{ct}ms \":\"" +
	   "%{pf}間前に作成されました, 作成にかかった時間: %{ct}ms\"" +
  "}}";

var lang_zht = "{" +
"\"values\":{" +
  "\"Summary\": \"概要\"," +
  "\"Log\": \"日誌\"," +
  "\"Tree\": \"樹\"," +
  "\"Blame\": \"責怪\"," +
  "\"Copy Lines\": \"複製線\"," +
  "\"Copy Link\": \"複製鏈接\"," +
  "\"View Blame\": \"看責怪\"," +
  "\"Remove Blame\": \"刪除責怪\"," +
  "\"Mode\": \"模式\"," +
  "\"Size\": \"尺寸\"," +
  "\"Name\": \"名稱\"," +
  "\"s\": \"秒\"," +
  "\"m\": \"分鐘\"," +
  "\"h\": \"小時\"," +
  "\" days\": \"天\"," +
  "\" weeks\": \"週\"," +
  "\" months\": \"個月\"," +
  "\" years\": \"年份\"," +
  "\"Branch Snapshot\": \"科快照\"," +
  "\"Tag Snapshot\": \"标签快照\"," +
  "\"Commit Snapshot\": \"提交快照\"," +
  "\"Description\": \"描述\"," +
  "\"Owner\": \"所有者\"," +
  "\"Branch\": \"科\"," +
  "\"Tag\": \"標籤\"," +
  "\"Author\": \"作者\"," +
  "\"Age\": \"年齡\"," +
  "\"Page fetched\": \"頁面已獲取\"," +
  "\"creation time\": \"創作時間\"," +
  "\"created\": \"創建\"," +
  "\"ago\": \"前\"," +
  "\"Message\": \"信息\"," +
  "\"Download\": \"下載\"," +
  "\"root\": \"根源\"," +
  "\"Committer\": \"提交者\"," +
  "\"Raw Patch\": \"原始補丁\"," +
  "\"Page fetched %{pf} ago, creation time: %{ct}ms " +
	   "(vhost etag hits: %{ve}%, cache hits: %{ch}%)\": " +
	"\"頁面%{pf}前獲取, 創作時間: %{ct}ms " +
	   "(vhost etag 緩存命中: %{ve}%, 緩存命中: %{ch}%)\"," +
  "\"Created %{pf} ago, creation time: %{ct}ms \":\"" +
	"%{pf}前創建, 創作時間: %{ct}ms \"" +
"}}";

var lang_zhs = "{" +
"\"values\":{" +
  "\"Summary\": \"概要\"," +
  "\"Log\": \"日志\"," +
  "\"Tree\": \"木\"," +
  "\"Blame\": \"归咎\"," +
  "\"Copy Lines\": \"复制线\"," +
  "\"Copy Link\": \"复制链接\"," +
  "\"View Blame\": \"看责备\"," +
  "\"Remove Blame\": \"删除责备\"," +
  "\"Mode\": \"模式\"," +
  "\"Size\": \"尺寸\"," +
  "\"Name\": \"名称\"," +
  "\"s\": \"秒\"," +
  "\"m\": \"分钟\"," +
  "\"h\": \"小时\"," +
  "\" days\": \"天\"," +
  "\" weeks\": \"周\"," +
  "\" months\": \"个月\"," +
  "\" years\": \"年份\"," +
  "\"Branch Snapshot\": \"科快照\"," +
  "\"Tag Snapshot\": \"标签快照\"," +
  "\"Commit Snapshot\": \"提交快照\"," +
  "\"Description\": \"描述\"," +
  "\"Owner\": \"所有者\"," +
  "\"Branch\": \"科\"," +
  "\"Tag\": \"标签\"," +
  "\"Author\": \"作者\"," +
  "\"Age\": \"年龄\"," +
  "\"Page fetched\": \"页面已获取\"," +
  "\"creation time\": \"创作时间\"," +
  "\"created\": \"创建\"," +
  "\"ago\": \"前\"," +
  "\"Message\": \"信息\"," +
  "\"Download\": \"下载\"," +
  "\"root\": \"根源\"," +
  "\"Committer\": \"提交者\"," +
  "\"Raw Patch\": \"原始补丁\"," +
  "\"Page fetched %{pf} ago, creation time: %{ct}ms " +
	   "(vhost etag hits: %{ve}%, cache hits: %{ch}%)\": " +
	"\"页面%{pf}前获取, 创作时间: %{ct}ms " +
	   "(vhost etag 缓存命中: %{ve}%, 缓存命中: %{ch}%)\"," +
   "\"Created %{pf} ago, creation time: %{ct}ms \":" +
		"\"%{pf}前创建, 创作时间: %{ct}ms \"" +
"}}";

const SaiAuthState = {
	NOT_LOGGED_IN: 0,
	LOGGED_IN_NO_GRANT: 1,
	LOGGED_IN_GRANT_USER: 2,   // < :2
	LOGGED_IN_GRANT_ADMIN: 3   // >= :2
};

var logs = "", redpend = 0, gitohashi_integ = 0, authd = 0, auth_is_admin = 0, auth_grant_level = -1, auth_state = SaiAuthState.NOT_LOGGED_IN, exptimer, auth_user = "",
active_terminals = {};
	logAnsiState = {}, logs_pending = "", lines_pending = "", times_pending = "",
	ongoing_task_activities = {}, last_log_timestamp = 0, last_log_uid = 0, spreadsheet_data_cache = {}, loadreport_data_cache = {},
	watcher_services = [],
	fadingTasks = new Map();

var segment_stack = [];
var seg_counter = 0;

window.addEventListener('beforeunload', () => {
	for (const task_uuid in active_terminals) {
		const closeMsg = {
			schema: "com.warmcat.sai.closeshell",
			task_uuid: task_uuid
		};
		if (typeof sai !== 'undefined' && sai && sai.readyState === WebSocket.OPEN) {
			sai.send(JSON.stringify(closeMsg));
		}
	}
});

/* Global caches for reconcilation */
var pcon_topology = {};
var pcon_energy_cache = {};
var last_builder_list = [];
var current_overview_offset = 0;

window.change_page = function(new_offset) {
	current_overview_offset = new_offset;
	sai_sb_request_overview(current_overview_offset);
};

function createPconDiv(pcon) {
    const pconDiv = document.createElement("div");
    pconDiv.className = "pcon";
    pconDiv.id = "pcon-" + pcon.name;
    pconDiv.style.marginLeft = "10px";
    pconDiv.style.borderLeft = "1px solid #ccc";
    pconDiv.style.paddingLeft = "5px";

    const header = document.createElement("div");
    header.className = "pcon-header";

    let stateClass = (pcon.on === 1) ? "pcon-on" : "pcon-off";
    let type = pcon.type ? `(${pcon.type})` : "";

    header.innerHTML = `<span class="${stateClass}">&#x23FB;</span> <b>${hsanitize(pcon.name)}</b> <span class="pcon-type">${hsanitize(type)}</span>`;
    pconDiv.appendChild(header);

    const childrenDiv = document.createElement("div");
    childrenDiv.className = "pcon-children";
    pconDiv.appendChild(childrenDiv);

    return pconDiv;
}

function renderPconHierarchy(container) {
    if (!container) return;

    /* Clear and redraw for now to ensure structure is correct */
    container.innerHTML = "";

    const pcons = Object.values(pcon_topology);
    /* Build map for dependency resolution */
    const pconMap = {};
    pcons.forEach(p => {
        p.children = []; /* Reset children */
        pconMap[p.name] = p;
    });

    /* Link PCONs */
    const roots = [];
    pcons.forEach(p => {
        if (p.depends_on && pconMap[p.depends_on]) {
            pconMap[p.depends_on].children.push(p);
        } else {
            roots.push(p);
        }
    });

    /* Sort roots and children by name */
    const sortByName = (a, b) => a.name.localeCompare(b.name);
    roots.sort(sortByName);
    pcons.forEach(p => p.children.sort(sortByName));

    /* Helper to recursively render PCONs and their builders */
    function renderPcon(pcon, parentDiv) {
        const div = createPconDiv(pcon);
        parentDiv.appendChild(div);
        const childrenContainer = div.querySelector(".pcon-children");

        /* Render builders belonging to this PCON */
        /* We search the global builder list for those matching this pcon */
        const myBuilders = last_builder_list.filter(b => b.pcon === pcon.name);
        myBuilders.sort((a, b) => a.name.localeCompare(b.name));

        if (myBuilders.length > 0) {
            const table = document.createElement("table");
            table.className = "builders";
            const tbody = document.createElement("tbody");
            table.appendChild(tbody);
            myBuilders.forEach(b => {
                tbody.appendChild(createBuilderRow(b));
            });
            childrenContainer.appendChild(table);
        }

        /* Render child PCONs */
        pcon.children.forEach(child => {
            renderPcon(child, childrenContainer);
        });
    }

    roots.forEach(root => {
        renderPcon(root, container);
    });

    /* Render orphan builders (no pcon or unknown pcon) */
    const orphanBuilders = last_builder_list.filter(b => !b.pcon || !pcon_topology[b.pcon]);
    if (orphanBuilders.length > 0) {
        const orphanDiv = document.createElement("div");
        orphanDiv.className = "pcon-orphans";
        orphanDiv.innerHTML = "<div class='pcon-header'><b>Unmanaged Builders</b></div>";
        const childrenContainer = document.createElement("div");
        childrenContainer.className = "pcon-children";
        orphanDiv.appendChild(childrenContainer);

        const table = document.createElement("table");
        table.className = "builders";
        const tbody = document.createElement("tbody");
        table.appendChild(tbody);
        orphanBuilders.forEach(b => {
            tbody.appendChild(createBuilderRow(b));
        });
        childrenContainer.appendChild(table);

        container.appendChild(orphanDiv);
    }
}

function update_task_activities() {
	for (const uuid in ongoing_task_activities) {
		const cat = ongoing_task_activities[uuid];
		[ document.getElementById("taskstate_" + uuid),
		  document.getElementById("tt_" + uuid) ].forEach(function(el) {
			if (!el)
				return;
			el.classList.remove("activity-1", "activity-2", "activity-3");
			if (cat > 0) {
				el.classList.add("activity-" + cat);
			}
		});
	}
}

function expiry()
{
	location.reload();
}

function san(s)
{
	var table = {
		'<': 'lt',
		'>': 'gt',
		'"': 'quot',
		'\'': 'apos',
		'&': 'amp'
	};

	return s.toString().replace(/[<>"'&]/g, function(chr) {
		return '&' + table[chr] + ';';
	});
}

function humanize(s)
{
	var i = parseInt(s, 10);

	if (i >= (1024 * 1024 * 1024))
		return (i / (1024 * 1024 * 1024)).toFixed(3) + "Gi";

	if (i >= (1024 * 1024))
		return (i / (1024 * 1024)).toFixed(3) + "Mi";

	if (i > 1024)
		return (i / 1024).toFixed(3) + "Ki";

	return s;
}

function flush_segments() {
	var target_id = segment_stack.length > 0 ? segment_stack[segment_stack.length - 1].id : "root";
	var c_idx = segment_stack.length > 0 ? (segment_stack[segment_stack.length - 1].chunk_index || 0) : 0;
	
	var logs_dom = target_id === "root" ? "logs" : ("dlogs-" + target_id + "-" + c_idx);
	var lines_dom = target_id === "root" ? "dlogsn" : ("dlogsn-" + target_id + "-" + c_idx);
	var times_dom = target_id === "root" ? "dlogst" : ("dlogst-" + target_id + "-" + c_idx);
	
	if (document.getElementById(logs_dom) && logs_pending) {
		document.getElementById(logs_dom).insertAdjacentHTML('beforeend', logs_pending);
	}
	if (document.getElementById(lines_dom) && lines_pending) {
		document.getElementById(lines_dom).insertAdjacentHTML('beforeend', lines_pending);
	}
	if (document.getElementById(times_dom) && times_pending) {
		document.getElementById(times_dom).insertAdjacentHTML('beforeend', times_pending);
	}
	
	logs_pending = lines_pending = times_pending = "";
	
	if (target_id !== "root") {
		var seg = segment_stack[segment_stack.length - 1];
		var ehdr = document.getElementById("hdr-seg-" + target_id);
		if (ehdr) {
			ehdr.querySelector('.seg-lines').innerText = seg.lines_count;
			var errSpan = ehdr.querySelector('.seg-errors');
			
			if (seg.error_count > 0) {
				errSpan.innerText = seg.error_count + " errors";
				ehdr.classList.add("has-error");
				errSpan.parentElement.classList.add("seg-errors-bold");
			} else if (seg.warning_count > 0) {
				ehdr.classList.add("has-warning");
			}
		}
	}
}

function append_chunk_table(id, chunk_index, target_dom) {
	var html = '<table><tr>' +
		'<td class="atop"><div class="dlogsn" id="dlogsn-' + id + '-' + chunk_index + '"></div></td>' +
		'<td class="atop"><div class="dlogst" id="dlogst-' + id + '-' + chunk_index + '"></div></td>' +
		'<td class="atop"><div class="dlogs"><span class="nowrap" id="dlogs-' + id + '-' + chunk_index + '"></span></div></td>' +
	'</tr></table>';
	if (target_dom) target_dom.insertAdjacentHTML('beforeend', html);
}

function push_segment(title, default_folded) {
	flush_segments();
	seg_counter++;
	var id = seg_counter;
	
	var seg = { id: id, title: title, lines_count: 0, error_count: 0, warning_count: 0, folded: default_folded, chunk_index: 0, auto_unfolded: false, user_toggled: false };
	
	var parent_id = segment_stack.length > 0 ? segment_stack[segment_stack.length - 1].id : "root";
	// Append to root's dlogs container OR the parent segment's BODY container
	var parent_logs_dom = parent_id === "root" ? "dlogs" : ("seg-" + parent_id);
	var parent_dom = document.getElementById(parent_logs_dom);
	
	if (parent_dom) {
		var icon = default_folded ? "▶" : "▼";
		var hideClass = default_folded ? " hide" : "";
		
		var clean_title = title.replace(/^[\s\S]*?(?:>|&gt;)saib(?:>|&gt;)\s*/i, '');
		var html = '<div class="log-segment-wrapper">' +
			'<div class="log-segment-header" id="hdr-seg-' + id + '">' +
				'<table class="seg-header-table"><tr>' +
					'<td class="seg-td-icon"><span class="fold-icon">' + icon + '</span></td>' +
					'<td class="seg-td-lines"><span class="seg-lines">0</span> lines</td>' +
					'<td class="seg-td-errors"><span class="seg-errors"></span></td>' +
					'<td class="seg-td-title"><span class="seg-title">' + hsanitize(clean_title) + '</span></td>' +
				'</tr></table>' +
			'</div>' +
			'<div class="log-segment-body' + hideClass + '" id="seg-' + id + '">' +
			'</div>' +
		'</div>';
		
		// If root, we only append once, but wait, root is just flat.
		parent_dom.insertAdjacentHTML('beforeend', html);
		
		var seg_dom = document.getElementById("seg-" + id);
		append_chunk_table(id, 0, seg_dom);
		
		if (parent_id === "root") {
			if (document.getElementById("dlogsn")) document.getElementById("dlogsn").insertAdjacentHTML('beforeend', '<br><br>');
			if (document.getElementById("dlogst")) document.getElementById("dlogst").insertAdjacentHTML('beforeend', '<br><br>');
		}
	}
	segment_stack.push(seg);
}

function pop_segment() {
	if (segment_stack.length > 0) {
		flush_segments();

		var p = segment_stack[segment_stack.length - 1];
		if (p.auto_unfolded && p.error_count === 0 && !p.user_toggled) {
			var body = document.getElementById("seg-" + p.id);
			var hdr = document.getElementById("hdr-seg-" + p.id);
			if (body && !body.classList.contains("hide")) {
				body.classList.add("hide");
				if (hdr) {
					var icon = hdr.querySelector('.fold-icon');
					if (icon) icon.innerText = "▶";
				}
			}
		}

		segment_stack.pop();
		
		// When we return to parent, we need a new table below the children we just popped
		if (segment_stack.length > 0) {
			var p = segment_stack[segment_stack.length - 1];
			p.chunk_index++;
			var seg_dom = document.getElementById("seg-" + p.id);
			append_chunk_table(p.id, p.chunk_index, seg_dom);
		}
	}
}

function toggleSegment(id) {
	for (var i = 0; i < segment_stack.length; i++) {
		if (segment_stack[i].id == id) {
			segment_stack[i].user_toggled = true;
			break;
		}
	}
	var body = document.getElementById("seg-" + id);
	var hdr = document.getElementById("hdr-seg-" + id);
	if (body && hdr) {
		var icon = hdr.querySelector('.fold-icon');
		if (body.classList.contains("hide")) {
			body.classList.remove("hide");
			if (icon) icon.innerText = "▼";
		} else {
			body.classList.add("hide");
			if (icon) icon.innerText = "▶";
		}
	}
}

function ansiToHtml(text, state) {
    const classMap = {
        '1': 'ansi-bold', '4': 'ansi-underline',
        '30': 'ansi-fg-black', '31': 'ansi-fg-red', '32': 'ansi-fg-green', '33': 'ansi-fg-yellow', '34': 'ansi-fg-blue', '35': 'ansi-fg-magenta', '36': 'ansi-fg-cyan', '37': 'ansi-fg-white',
        '40': 'ansi-bg-black', '41': 'ansi-bg-red', '42': 'ansi-bg-green', '43': 'ansi-bg-yellow', '44': 'ansi-bg-blue', '45': 'ansi-bg-magenta', '46': 'ansi-bg-cyan', '47': 'ansi-bg-white',
    };

    // Ensure state is a valid object
    state = state || {};
    let currentClasses = new Set(state.classes || []);
    let currentLink = state.linkHref || null;

    const parts = text.split(/(\u001b\[[0-9:;<=>?]*[ -/]*[@-~]|\u001b\]8;.*?(?:\u001b\\|\x07))/);
    let html = '';

    for (const part of parts) {
        if (!part) continue;

        if (part.startsWith('\u001b[')) { // It's an ANSI code
            if (part.endsWith('m')) {
                const codes = part.substring(2, part.length - 1).split(';');

                for (let code of codes) {
                    if (code === '0' || code === '') {
                        currentClasses.clear();
                        continue;
                    }

                    /* handle leading zeros like 01 */
                    if (!classMap[code] && code.startsWith('0'))
                        code = code.substring(1);

                    if (classMap[code]) {
                        // Handle foreground/background colors: remove old before adding new
                        const icode = parseInt(code, 10);
                        if (icode >= 30 && icode <= 37) {
                            currentClasses.forEach(c => { if (c.startsWith('ansi-fg-')) currentClasses.delete(c); });
                        }
                        if (icode >= 40 && icode <= 47) {
                            currentClasses.forEach(c => { if (c.startsWith('ansi-bg-')) currentClasses.delete(c); });
                        }
                        currentClasses.add(classMap[code]);
                    }
                }
            }
            // Non-m sequences are just stripped (handled by the split and ignored here)
        } else if (part.startsWith('\u001b]8;')) { // OSC 8 Hyperlink
            let terminatorLen = part.endsWith('\x07') ? 1 : 2;
            let inner = part.substring(4, part.length - terminatorLen);
            let firstSemicolon = inner.indexOf(';');
            if (firstSemicolon !== -1) {
                let url = inner.substring(firstSemicolon + 1);
                if (url === "") {
                    currentLink = null;
                } else if (/^(https?|ftp|file|vscode):/i.test(url)) {
                    currentLink = url;
                }
            }
        } else { // It's plain text
            const sanitizedPart = hsanitize(part);
            let styledPart = sanitizedPart;
            if (currentClasses.size > 0) {
                styledPart = `<span class="${Array.from(currentClasses).join(' ')}">${styledPart}</span>`;
            }
            if (currentLink) {
                let safelink = hsanitize(currentLink);
                styledPart = `<a href="${safelink}" target="_blank" rel="noopener noreferrer">${styledPart}</a>`;
            }
            html += styledPart;
        }
    }

    return {
        html: html,
        newState: { classes: Array.from(currentClasses), linkHref: currentLink }
    };
}

function hsanitize(s)
{
	var table = {
		'<': 'lt',
		'>': 'gt',
		'"': 'quot',
		'\'': 'apos',
		'&': 'amp'
	};

	return s.toString().replace(/[<>"'&]/g, function(chr) {
		return '&' + table[chr] + ';';
	}).replace(/\r\n/g, '\n').replace(/\n/g, '<br>');
}

function createTaskRow(task, now_ut) {
    const tr = document.createElement("tr");
    tr.id = "task-row-" + task.task_uuid;

    let s1 = "";
    let qc;
    for (qc = 0; qc <= task.build_step; qc++)
        s1 += "&#9635;";
    while (qc <= task.total_steps) {
        s1 += "&#9633;";
        qc++;
    }

    let prefix = "";
    if (task.git_hash && task.repo_name) {
        prefix = `<span class="e6">${hsanitize(task.git_hash.substring(0, 4))}</span> ${hsanitize(task.repo_name)} `;
    }

    tr.innerHTML = `<td>${s1}</td>` +
                   `<td>${agify(now_ut, task.started)} ago</td>` +
                   `<td>${prefix}<a href="index.html?task=${hsanitize(task.task_uuid)}">${hsanitize(task.task_name)}</a></td>`;
    return tr;
}

function updateTaskRow(tr, task, now_ut) {
    let s1 = "";
    let qc;
    for (qc = 0; qc <= task.build_step; qc++)
        s1 += "&#9635;";
    while (qc <= task.total_steps) {
        s1 += "&#9633;";
        qc++;
    }
    let prefix = "";
    if (task.git_hash && task.repo_name) {
        prefix = `<span class="e6">${hsanitize(task.git_hash.substring(0, 4))}</span> ${hsanitize(task.repo_name)} `;
    }

    const newHTML = `<td>${s1}</td>` +
                   `<td>${agify(now_ut, task.started)} ago</td>` +
                   `<td>${prefix}<a href="index.html?task=${hsanitize(task.task_uuid)}">${hsanitize(task.task_name)}</a></td>`;
    
    if (tr.innerHTML !== newHTML) {
        tr.innerHTML = newHTML;
    }
}

function updateSpreadsheetDOM(container, tasks) {
	if (!tasks || !tasks.length) {
		container.innerHTML = "";
		return;
	}

    tasks.sort((a, b) => b.started - a.started || a.task_name.localeCompare(b.task_name));

    let table = container.querySelector("table.spreadsheet");
    if (!table) {
        container.innerHTML = '<table class="spreadsheet">' +
            '<thead><tr><th>Build Step</th><th>Since</th><th>Task</th></tr></thead>' +
            '<tbody></tbody></table>';
        table = container.querySelector("table.spreadsheet");
    }
    const tbody = table.querySelector("tbody");
    const now_ut = Math.round((new Date().getTime() / 1000));

    const existingRows = new Map();
    for (const row of tbody.children) {
        existingRows.set(row.id, row);
    }

    const newOrUpdatedTaskIds = new Set();
    for (const task of tasks) {
        const taskRowId = "task-row-" + task.task_uuid;
        newOrUpdatedTaskIds.add(taskRowId);
        const row = existingRows.get(taskRowId);

        if (row) {
            if (fadingTasks.has(task.task_uuid)) {
                clearTimeout(fadingTasks.get(task.task_uuid));
                fadingTasks.delete(task.task_uuid);
                row.classList.remove("fading-out");
            }
            updateTaskRow(row, task, now_ut);
        } else {
            tbody.appendChild(createTaskRow(task, now_ut));
        }
    }

    for (const [rowId, row] of existingRows) {
        if (!newOrUpdatedTaskIds.has(rowId)) {
            const task_uuid = rowId.substring(9);
            if (!fadingTasks.has(task_uuid)) {
                row.classList.add("fading-out");
                const timer = setTimeout(() => {
                    tbody.removeChild(row);
                    fadingTasks.delete(task_uuid);
                }, 3000);
                fadingTasks.set(task_uuid, timer);
            }
        }
    }

    const rows = Array.from(tbody.children);
    const taskMap = new Map(tasks.map(t => ["task-row-" + t.task_uuid, t]));

    rows.sort((rowA, rowB) => {
        const taskA = taskMap.get(rowA.id);
        const taskB = taskMap.get(rowB.id);
        if (!taskA || !taskB) return 0;
        return (taskB.started - taskA.started) || taskA.task_name.localeCompare(taskB.task_name);
    });

    for (let i = 0; i < rows.length; i++) {
        const expectedRow = rows[i];
        if (tbody.children[i] !== expectedRow) {
            tbody.insertBefore(expectedRow, tbody.children[i] || null);
        }
    }
}

var pos = 0, lli = 1, lines = "", times = "", locked = 1, tfirst = 0,
		cont = [ 0, 0, 0, 0, 0];
var deleted_events_cache = new Set();
var loaded_events = [], selected_event_uuid = null, selected_task_uuid = null, total_events = 0, current_offset = 0;

/*
 * Sidebar (merged top pane) state.  The user picks a project (col 2), then a
 * branch (col 3); col 4 lists that project+branch's events newest-first.
 * sb_projects / sb_branches are the unique values advertised by the server.
 */
var sb_projects = [], sb_branches = [];
/*
 * Latest non-deleted event state per ref for the selected project, as reported
 * by the branchlist reply (ref -> state int).  Used to colour branch rows by
 * the build result of their newest event.  Empty when no project is selected
 * or when an older server omits branch_states.
 */
var sb_branch_states = {};
var sb_selected_project = null, sb_selected_ref = null;

/*
 * Send an overview (taskinfo) request scoped to the current sidebar
 * selection.  An empty project/ref means "no constraint".
 */
function sai_sb_request_overview(offset)
{
	var o = (typeof offset === 'number') ? offset : 0;
	sai.send("{\"schema\":\"com.warmcat.sai.taskinfo\"," +
		 "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
		 "\"offset\": " + o + "," +
		 "\"project\":" + JSON.stringify(sb_selected_project || "") + "," +
		 "\"ref\":" + JSON.stringify(sb_selected_ref || "") + "}");
}

function sai_sb_request_projects()
{
	sai.send("{\"schema\":\"com.warmcat.sai.projlist\"}");
}

function sai_sb_request_branches(project)
{
	sai.send("{\"schema\":\"com.warmcat.sai.branchlist\"," +
		 "\"project\":" + JSON.stringify(project || "") + "}");
}

function sai_event_hash_display(hash) {
	if (!hash) return "";
	return "sai-" + hash.substring(0, 8);
}

/*
 * If the event was notified with a repository weburl (the base URL of the
 * repo's gitweb, eg gitohashi), render `text` as a link into it; otherwise
 * return the plain sanitized text.  suffix is appended to the weburl:
 *   ""                       -> the repo summary page
 *   "/log?h=<ref>"           -> the log of that branch / tag
 *   "/log?id=<commit hash>"  -> that commit
 */
function sai_weburl_link(e, suffix, text) {
	if (!e || !e.weburl)
		return san(text);

	return "<a href=\"" + san(e.weburl + (suffix || "")) + "\">" +
			san(text) + "</a>";
}

function get_appropriate_ws_url()
{
	var pcol;
	var u = document.URL;

	/*
	 * We open the websocket encrypted if this page came on an
	 * https:// url itself, otherwise unencrypted
	 */

	if (u.substring(0, 5) === "https") {
		pcol = "wss://";
		u = u.substr(8);
	} else {
		pcol = "ws://";
		if (u.substring(0, 4) === "http")
			u = u.substr(7);
	}

	u = u.split("/");

	return pcol + u[0];
}

var age_names = [  "s",  "m",    "h", " days", " weeks", " months", " years" ];
var age_div =   [   1,   60,   3600,   86400,   604800,   2419200,  31536000  ];
var age_limit = [ 120, 7200, 172800, 1209600,  4838400,  63072000,         0  ];
var age_upd   = [   5,   10,    300,    1800,     3600, 12 * 3600, 12 * 3600  ];

function agify(now, secs)
{
	var d = now - secs, n;

	if (!secs)
		return "";

	if (secs > now)
		d = secs - now;

	for (n = 0; n < age_names.length; n++)
		if (d < age_limit[n] || age_limit[n] === 0)
			return "<span class='age-" + n + "' ut='" + secs +
				"'>" + ((secs > now) ? "in " : "") + Math.ceil(d / age_div[n]) +
				i18n(age_names[n]) + "</span>";
}

var aging_timer = null;

function aging()
{
	var n, next = 24 * 3600,
	    now_ut = Math.round((new Date().getTime() / 1000));

	var selector = [];
	for (n = 0; n < age_names.length; n++)
		selector.push(".age-" + n);

	var elems = document.querySelectorAll(selector.join(", "));
	var list = [];
	for (n = 0; n < elems.length; n++)
		list.push(elems[n]);

	for (n = 0; n < list.length; n++) {
		var e = list[n];
		var secs = e.getAttribute("ut");
		var d = Math.abs(now_ut - secs);

		for (var j = 0; j < age_limit.length; j++) {
			if (d < age_limit[j] || age_limit[j] === 0) {
				if (age_upd[j] < next)
					next = age_upd[j];
				break;
			}
		}

		e.outerHTML = agify(now_ut, secs);
	}

	if (next < 5)
		next = 5;

	/*
	 * We only need to come back when the age might have changed.
	 * Eg, if everything is counted in hours already, once per
	 * 5 minutes is accurate enough.
	 */
	if (aging_timer)
		clearTimeout(aging_timer);
	aging_timer = window.setTimeout(aging, next * 1000);
}
var sai, jso, s, sai_arts = "";

function sai_plat_icon(plat, size)
{
	var s, s1 = "";

	s = plat.split('/');
	if (s[0]) {
	// console.log("plat " + plat + " plat[0] " + s[0]);
	s1 = "<img class=\"ip" + size + " zup\" src=\"/sai/" + san(s[0]) +
		".svg\">";

	if (s[1])
		s1 += "<img class=\"ip" + size + " tread1\" src=\"/sai/arch-" + san(s[1]) + ".svg\">";
	}

	if (s[2]) {
		s1 += "<img class=\"ip" + size + " tread2\" src=\"/sai/tc-" + san(s[2]) + ".svg\">";
	}
	return s1;
}

function sai_stateful_taskname(state, nm, sf)
{
	var tp = "";

	if (sf)
		return "<span id=\"taskstate\" class=\"ti2 taskstate" +
			state + "\">&nbsp;" + san(nm) + "&nbsp;&nbsp;</span>";

	if (state == 4 || state == 6)
		tp = " ov_bad";

	return "<span id=\"taskstate\" class=\"ti2 " + tp + "\">" + san(nm) + "</span>";
}

function sai_taskinfo_render(t, now_ut)
{
	var now_ut = Math.round((new Date().getTime() / 1000));
	var s = "";

	s = "<table><tr class=\"nomar\"><td class=\"atop\"><table>" +
		sai_event_render(t, now_ut, 0) + "</table></td><td class=\"ti\">" +
		"<span class=\"ti1\">" + sai_plat_icon(t.t.platform, 2) +
		san(t.t.builder_name ? t.t.builder_name : t.t.platform) + "</span>&nbsp;" +
		sai_stateful_taskname(t.t.state, t.t.taskname, 1) + "&nbsp;&nbsp;";
	if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN && t.t.state != 0 && t.t.state != 3 && t.t.state != 4 && t.t.state != 5)
		s += "<img class=\"rebuild\" alt=\"stop build\" src=\"stop.svg\" " +
			"id=\"stop-" + san(t.t.uuid) + "\">&nbsp;";
	if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN)
		s += "<img class=\"rebuild\" alt=\"rebuild\" src=\"rebuild.png\" " +
			"id=\"rebuild-" + san(t.t.uuid) + "\">&nbsp;";

	if (t.t.builder_name) {
		var now_ut = Math.round((new Date().getTime() / 1000));

		if (t.t.started)
		/* started is a unix time, in seconds */
		s += "<span class=\"ti5\"> " +
		     agify(now_ut, t.t.started) + " ago, Dur: " +
		     sai_tt_fmt_dur(sai_tt_dur_secs(t.t, now_ut)) +
			"</span><div id=\"sai_arts\"></div><div id=\"metrics-summary-" + san(t.t.uuid) + "\"></div>";
		sai_arts = "";
	}

	if (t.runs && t.runs.length >= 2) {
		s += "<div class=\"runs-header-container\" style=\"display:flex; flex-wrap:wrap; gap:6px; margin-top:2px;\">";
		for (var n = t.runs.length - 1; n >= 0; n--) {
			var r = t.runs[n];
			var ridx = typeof r.run !== 'undefined' ? r.run : 0;
			var current = (ridx == (typeof t.t.run !== 'undefined' ? t.t.run : 0));
			var dcl = current ? "run-current-decal" : "run-decal";
			var timeStr = r.started ? agify(now_ut, r.started) + " ago" : "pending";
			var decal = "<div class=\"taskstate taskstate" + r.state + " " + dcl + "\" style=\"padding:4px; text-align:center; border-radius:6px;\">" +
				"<a href=\"index.html?task=" + t.t.uuid + "&run=" + ridx + "\" style=\"text-decoration:none; color:inherit; display:block;\">" +
				"<div>" + sai_plat_icon(r.platform, 0) + "</div>" +
				"<div class=\"ti5\" style=\"margin-top:2px;\">" + timeStr + "</div>" +
				"</a></div>";
			s += decal;
		}
		s += "</div>";
	}

	s += "</td></tr>";

	s += "</td></tr></table></table>";

	return s;
}

function update_summary_and_progress(event_uuid) {
    var sumbs = document.getElementById("sumbs-" + event_uuid);
    if (!sumbs) {
	/*
	 * No legacy combined slot; the sidebar row (if present) is refreshed
	 * separately by sai_sb_render_event_summary().
	 */
	sai_sb_render_event_summary(event_uuid);
        return;
    }

    var summary = summarize_build_situation(event_uuid);
    var summary_html = summary.text;

    if (summary.total > 0 && summary.good !== summary.total) {
        var good_pct = (summary.good / summary.total) * 100;
        var pending_pct = (summary.pending / summary.total) * 100;
        var ongoing_pct = (summary.ongoing / summary.total) * 100;
        var bad_pct = (summary.bad / summary.total) * 100;

        var roundUpTo5 = function(n) {
            return Math.ceil(n / 5) * 5;
        };

        var good_w = roundUpTo5(good_pct);
        var pending_w = roundUpTo5(pending_pct);
        var ongoing_w = roundUpTo5(ongoing_pct);
        var bad_w = roundUpTo5(bad_pct);

        var total_w = good_w + pending_w + ongoing_w + bad_w;

        if (total_w > 100) {
            var surplus = total_w - 100;
            var widths = {good: good_w, pending: pending_w, ongoing: ongoing_w, bad: bad_w};

            var largest_key = Object.keys(widths).reduce(function(a, b){ return widths[a] > widths[b] ? a : b });

            widths[largest_key] -= surplus;

            good_w = widths.good;
            pending_w = widths.pending;
            ongoing_w = widths.ongoing;
            bad_w = widths.bad;
        }

        var good_cls = "w-" + good_w;
        var pending_cls = "w-" + pending_w;
        var ongoing_cls = "w-" + ongoing_w;
        var bad_cls = "w-" + bad_w;

        summary_html += "<div class=\"progress-bar\">" +
            "<div class=\"progress-bar-success " + good_cls + "\"></div>" +
            "<div class=\"progress-bar-ongoing " + ongoing_cls + "\"></div>" +
            "<div class=\"progress-bar-pending " + pending_cls + "\"></div>" +
            "<div class=\"progress-bar-failed float-right " + bad_cls + "\"></div>" +
            "</div>";
    }
    sumbs.innerHTML = summary_html;

    /* keep the sidebar row (if any) in sync too */
    sai_sb_render_event_summary(event_uuid);
}

/*
 * Build the HTML for an event's progress bar (or "" when complete / empty).
 */
function sai_sb_progress_bar_html(summary)
{
    if (!summary || !summary.total || summary.good === summary.total)
	return "";

    var good_pct  = (summary.good / summary.total) * 100;
    var pend_pct  = (summary.pending / summary.total) * 100;
    var ong_pct   = (summary.ongoing / summary.total) * 100;
    var bad_pct   = (summary.bad / summary.total) * 100;

    var up5 = function(n) { return Math.ceil(n / 5) * 5; };
    var gw = up5(good_pct), pw = up5(pend_pct), ow = up5(ong_pct), bw = up5(bad_pct);
    var tw = gw + pw + ow + bw;
    if (tw > 100) {
	var widths = { g: gw, p: pw, o: ow, b: bw };
	var largest = Object.keys(widths).reduce(function(a, b){
				return widths[a] > widths[b] ? a : b; });
	widths[largest] -= (tw - 100);
	gw = widths.g; pw = widths.p; ow = widths.o; bw = widths.b;
    }

    return "<div class=\"progress-bar\">" +
	"<div class=\"progress-bar-success w-" + gw + "\"></div>" +
	"<div class=\"progress-bar-ongoing w-" + ow + "\"></div>" +
	"<div class=\"progress-bar-pending w-" + pw + "\"></div>" +
	"<div class=\"progress-bar-failed float-right w-" + bw + "\"></div>" +
	"</div>";
}

/*
 * Refresh the sidebar event row's status text (#sbsum-<uuid>) and progress bar
 * (#sbbar-<uuid>) independently, so the status text isn't duplicated.
 */
function sai_sb_render_event_summary(event_uuid)
{
    var sbs = document.getElementById("sbsum-" + event_uuid);
    var bar = document.getElementById("sbbar-" + event_uuid);
    if (!sbs && !bar)
	return;
    var sum = summarize_build_situation(event_uuid);
    if (sbs)
	sbs.innerHTML = san(sum.text || "");
    if (bar)
	bar.innerHTML = sai_sb_progress_bar_html(sum);
}

function summarize_build_situation(event_uuid)
{
	var good = 0, bad = 0, total = 0, ongoing = 0, pending = 0;
	var ev_obj = null;
	if (typeof loaded_events !== 'undefined' && loaded_events) {
		ev_obj = loaded_events.find(o => o.e.uuid === event_uuid);
	}

	/*
	 * Sidebar-scoped overview events arrive with an empty task array but a
	 * server-computed "summary" string (shipping full task lists for many
	 * events overflows the server's buflist).  Prefer that summary when the
	 * task array isn't present.
	 */
	if (ev_obj && (!ev_obj.t || !ev_obj.t.length) && ev_obj.summary) {
		var sc = ev_obj.sum_counts || {};
		return {
			text: ev_obj.summary,
			good: sc.good || 0,
			bad: sc.bad || 0,
			ongoing: sc.ongoing || 0,
			pending: sc.pending || 0,
			total: sc.total || 0
		};
	}

	if (ev_obj && ev_obj.t) {
		var run_max = {};
		for (var q = 0; q < ev_obj.t.length; q++) {
			var tx = ev_obj.t[q];
			var ru = typeof tx.run !== 'undefined' ? tx.run : 0;
			if (typeof run_max[tx.uuid] === 'undefined' || ru > (typeof run_max[tx.uuid].run !== 'undefined' ? run_max[tx.uuid].run : 0))
				run_max[tx.uuid] = tx;
		}

		for (var uid in run_max) {
			var t = run_max[uid];
			if (t.idle)
				continue;
			total++;
			switch (t.state) {
				case 0: pending++; break;
				case 1:
				case 2:
				case 6: ongoing++; break;
				case 3: good++; break;
				case 4:
				case 5: bad++; break;
			}
		}
	} else {
		var roo = document.getElementById("taskcont-" + event_uuid);
		if (!roo)
			return { text: "" };

		var same = roo.querySelectorAll(".taskstate:not(.run-decal):not(.idle-lane)");
		if (same)
			total = same.length;
		same = roo.querySelectorAll(".taskstate0:not(.run-decal):not(.idle-lane)");
		if (same)
			pending = same.length;
		same = roo.querySelectorAll(".taskstate1:not(.run-decal):not(.idle-lane)");
		if (same)
			ongoing += same.length;
		same = roo.querySelectorAll(".taskstate2:not(.run-decal):not(.idle-lane)");
		if (same)
			ongoing += same.length;
		same = roo.querySelectorAll(".taskstate3:not(.run-decal):not(.idle-lane)");
		if (same)
			good = same.length;
		same = roo.querySelectorAll(".taskstate4:not(.run-decal):not(.idle-lane)");
		if (same)
			bad += same.length;
		same = roo.querySelectorAll(".taskstate5:not(.run-decal):not(.idle-lane)");
		if (same)
			bad += same.length;
		same = roo.querySelectorAll(".taskstate6:not(.run-decal):not(.idle-lane)");
		if (same)
			ongoing += same.length;
	}

	var text;
	if (good == total && total > 0)
		text = "All " + good + " passed";
	else if (bad == total && total > 0)
		text = "All " + bad + " failed";
	else if (pending == total && total > 0)
		text = total + " pending";
	else {
		var parts = [];
		if (good) parts.push("OK: " + good);
		if (bad) parts.push("Bad: " + bad);
		if (ongoing) parts.push("Building: " + ongoing);
		if (pending) parts.push("Wait: " + pending);
		text = parts.join(", ");
	}

	return {
		text: text,
		good: good,
		bad: bad,
		ongoing: ongoing,
		pending: pending,
		total: total
	};
}

function sai_watcher_render(w) {
	var s = "", svc = null;

	/* Find service definition */
	if (watcher_services && watcher_services.watchers) {
		watcher_services.watchers.forEach(sv => {
			if (sv.name === w.service_name) svc = sv;
		});
	}

	s = "<div class=\"watcher\" title=\"" + san(w.service_name) + "\">";
	s += "<a href=\"" + san(w.url) + "\" target=\"_blank\">";
	s += "<img src=\"/sai/watchers/" + san(w.service_name) + "/icon.svg\" class=\"watcher-icon\">";
	s += "</a>";

	if (w.metrics_json) {
		try {
			var m = JSON.parse(w.metrics_json);
			if (svc && svc.ui) {
				s += "<div class=\"watcher-metrics\">";
				svc.ui.forEach(u => {
					if (typeof m[u.key] !== 'undefined') {
						var val = m[u.key];
						var cl = "";
						if (typeof u.fail_if_gt !== 'undefined' && parseInt(val) > u.fail_if_gt) cl = " watcher-fail";
						else if (typeof u.warn_if_gt !== 'undefined' && parseInt(val) > u.warn_if_gt) cl = " watcher-warn";

						s += "<span class=\"watcher-metric" + cl + "\" title=\"" + san(u.label) + "\">" + san(val) + "</span>";
					}
				});
				s += "</div>";
			}
		} catch (e) { }
	}
	s += "</div>";

	return s;
}

function sai_event_summary_render(o, now_ut, reset_all_icon)
{
	var s, q, ctn = "", wai, s1 = "", n, e = o.e;

	s = "<table class=\"comp";

	if (!o.e)
		return;

	if (e.state == 3)
		s += " comp_pass";
	if (e.state == 4 || e.state == 6)
		s += " comp_fail";
	if (e.adhoc)
		s += " adhoc";

	s += "\"><tr><td class=\"jumble\"><a href=\"/sai/?event=" + san(e.uuid) +
		"\"><img src=\"/sai/sai-event.svg\"";
	if (gitohashi_integ)
		s += " class=\"saicon\"";
	if (e.state == 3 || e.state == 4)
		s += " class=\"deemph\"";
	s += ">";
	var cl = "evr";
	if (gitohashi_integ)
		cl = "evr_gi";
	if (e.state == 3)
		s += "<div class=\"" + cl + "\"><img src=\"/sai/passed.svg\"></div>";
	if (e.state == 4)
		s += "<div class=\"" + cl + "\"><img src=\"/sai/failed.svg\"></div>";

	s += "</a>";
	/*
	 * The per-event restart-all / delete-event buttons have moved to the
	 * tasks-section header (render_selected_event_tasks) and are no longer
	 * emitted inside the decal summary.
	 */
	s += "</td>";

	if (!gitohashi_integ) {
		s +=
		"<td><table class=\"nomar\">" +
		"<tr><td class=\"nomar\" colspan=2>" +
		"<span class=\"e1\">" + sai_weburl_link(e, "", e.repo_name);
		if (e.sec)
			s += " <img class=\"bico\" src=\"/sai/locked.svg\">";
		s += "</span></td></tr><tr><td class=\"nomar\" colspan=2><span class=\"e2\">";

		if (e.ref.substr(0, 11) === "refs/heads/") {
			s += "<img class=\"branch\">" +
				sai_weburl_link(e, "/log?h=" + encodeURIComponent(e.ref.substr(11)),
						 e.ref.substr(11));
		} else
			if (e.ref.substr(0, 10) === "refs/tags/") {
				s += "<img class=\"tag\">" +
					sai_weburl_link(e, "/log?h=" + encodeURIComponent(e.ref.substr(10)),
							 e.ref.substr(10));
			} else
				s += san(e.ref);

		s += "</span></td></tr><tr><td class=\"nomar e6\">" +
			sai_weburl_link(e, "/log?id=" + encodeURIComponent(e.hash),
					sai_event_hash_display(e.hash)) +
		     "</td><td class=\"e6 nomar\">" +
		     agify(now_ut, e.created) + "</td></tr>";
		 s += "</table>" +
		     "</td>";
	} else {
		s +="<td><table><tr><td class=\"e6 nomar\">" +
			sai_weburl_link(e, "/log?id=" + encodeURIComponent(e.hash),
					sai_event_hash_display(e.hash)) + " " +
			agify(now_ut, e.created) +
		     "</td></tr><tr><td class=\"nomar e6\" id=\"sumbs-" + e.uuid + "\"></td></tr>" +
		     "</table></td>";
	}
	s += "</tr>";

	if (o.watchers && o.watchers.length) {
		s += "<tr><td class=\"nomar\" colspan=\"2\"><div class=\"watchers-row\">";
		o.watchers.forEach(w => {
			s += sai_watcher_render(w);
		});
		s += "</div></td></tr>";
	}

	s += "<tr><td class=\"nomar e6\" colspan=\"2\" id=\"sumbs-" + e.uuid +"\"></td></tr></table>";

	return s;
}

function find_event_by_task_uuid(taskUuid) {
	if (!loaded_events) return null;
	for (var i = 0; i < loaded_events.length; i++) {
		var o = loaded_events[i];
		if (o.t) {
			for (var j = 0; j < o.t.length; j++) {
				if (o.t[j].uuid === taskUuid) {
					return o.e.uuid;
				}
			}
		}
	}
	return null;
}

/*
 * ---------------------------------------------------------------------------
 * Sidebar (merged top pane) rendering: projects (col 2), branches (col 3),
 * and the per-project+branch event list (col 4).  All build HTML via string
 * concatenation + innerHTML and attach handlers with addEventListener (no
 * inline styles or handlers, per the strict CSP).  Dynamic text is escaped
 * with san().
 * ---------------------------------------------------------------------------
 */

function sai_sb_fmt_when(secs)
{
	if (!secs)
		return "";
	var d = new Date(secs * 1000);
	/* compact "YYYY-MM-DD HH:MM" in UTC; the relative age is shown via agify */
	function p(n, l) { var s = "" + n; while (s.length < l) s = "0" + s; return s; }
	return p(d.getUTCFullYear(), 4) + "-" + p(d.getUTCMonth() + 1, 2) + "-" +
	       p(d.getUTCDate(), 2) + " " + p(d.getUTCHours(), 2) + ":" +
	       p(d.getUTCMinutes(), 2);
}

function sai_sb_short_ref(ref)
{
	if (!ref)
		return "";
	if (ref.substr(0, 11) === "refs/heads/")
		return ref.substr(11);
	if (ref.substr(0, 10) === "refs/tags/")
		return ref.substr(10);
	return ref;
}

function render_sb_projects()
{
	var c = document.getElementById("sai_sb_projects");
	if (!c)
		return;
	var s = "";
	if (!sb_projects || !sb_projects.length) {
		s = "<div class=\"sb-empty\">No projects</div>";
	} else {
		sb_projects.forEach(function(name) {
			var sel = (name === sb_selected_project) ? " selected" : "";
			s += "<div class=\"sb-row" + sel + "\" data-project=\"" +
			     san(name) + "\">" + san(name) + "</div>";
		});
	}
	c.innerHTML = s;
	c.querySelectorAll(".sb-row").forEach(function(row) {
		row.addEventListener("click", function() {
			selectSbProject(row.getAttribute("data-project"));
		});
	});
}

/*
 * Map a latest-event state to the same comp_pass / comp_fail class family the
 * event rows use, so a branch name is coloured by its newest build result.
 * Returns "" for ongoing / waiting states so they keep the default styling.
 */
function sai_sb_branch_state_class(ref)
{
	if (!sb_branch_states)
		return "";
	var st = sb_branch_states[ref];
	if (st === 3)
		return " comp_pass";
	if (st === 4 || st === 6)
		return " comp_fail";
	return "";
}

/*
 * The newest loaded event matching the current sidebar selection (project
 * and, if set, branch), or null if we hold no event for it yet.
 */
function sai_sb_newest_matching_event()
{
	if (!loaded_events || !loaded_events.length)
		return null;
	var ml = loaded_events.filter(function(o) {
		return o && o.e &&
			(!sb_selected_project ||
			 o.e.repo_name === sb_selected_project) &&
			(!sb_selected_ref || o.e.ref === sb_selected_ref);
	});
	if (!ml.length)
		return null;
	ml.sort(function(a, b) {
		return (b.e.created || 0) - (a.e.created || 0);
	});
	return ml[0];
}

/*
 * Live-update the selected branch's colour: the server only pushes scoped
 * events for the current selection, so only sb_selected_ref can have moved.
 * Recompute the newest matching event's state from loaded_events; if it differs
 * from the recorded sb_branch_states entry, update it and re-render col 3.
 */
function sai_sb_branch_state_livecheck()
{
	if (!sb_selected_ref || !sb_branch_states ||
	    !(sb_selected_ref in sb_branch_states))
		return;
	var newest = sai_sb_newest_matching_event();
	if (!newest)
		return;
	if (sb_branch_states[sb_selected_ref] !== newest.e.state) {
		sb_branch_states[sb_selected_ref] = newest.e.state;
		render_sb_branches();
	}
}

function render_sb_branches()
{
	var c = document.getElementById("sai_sb_branches");
	if (!c)
		return;
	var s = "";
	if (!sb_branches || !sb_branches.length) {
		s = "<div class=\"sb-empty\">No branches</div>";
	} else {
		sb_branches.forEach(function(ref) {
			var sel = (ref === sb_selected_ref) ? " selected" : "";
			var stClass = sai_sb_branch_state_class(ref);
			s += "<div class=\"sb-row" + stClass + sel +
			     "\" data-ref=\"" + san(ref) + "\">" +
			     san(sai_sb_short_ref(ref)) + "</div>";
		});
	}
	c.innerHTML = s;
	c.querySelectorAll(".sb-row").forEach(function(row) {
		row.addEventListener("click", function() {
			selectSbBranch(row.getAttribute("data-ref"));
		});
	});
}

/*
 * The newest-first event list (col 4) for the selected project + branch.
 * Filtered client-side from loaded_events, so a freshly-pushed matching
 * event appears at the top automatically on the next render.
 */
function render_sb_events()
{
	var c = document.getElementById("sai_sb_events");
	if (!c)
		return;
	var now_ut = Math.round((new Date().getTime() / 1000));

	/*
	 * Without a project + branch selected, col 4 stays empty (the events
	 * shown are scoped to the selection; showing "everything" would just
	 * mirror the old unscoped behaviour).
	 */
	if (!sb_selected_project && !sb_selected_ref) {
		c.innerHTML = "<div class=\"sb-empty\">Select a project and branch</div>";
		return;
	}

	var matching = [];
	if (loaded_events && loaded_events.length) {
		loaded_events.forEach(function(o) {
			if (!o || !o.e)
				return;
			if (sb_selected_project && o.e.repo_name !== sb_selected_project)
				return;
			if (sb_selected_ref && o.e.ref !== sb_selected_ref)
				return;
			matching.push(o);
		});
	}

	/* newest-first by creation time */
	matching.sort(function(a, b) {
		var ca = a.e.created || 0, cb = b.e.created || 0;
		return cb - ca;
	});

	var s = "";
	if (!matching.length) {
		s = "<div class=\"sb-empty\">No events</div>";
	} else {
		matching.forEach(function(o) {
			var e = o.e;
			var stateClass = "";
			if (e.state == 3) stateClass = " comp_pass";
			if (e.state == 4 || e.state == 6) stateClass = " comp_fail";
			var sel = (e.uuid === selected_event_uuid) ? " selected" : "";
			if (e.adhoc)
				stateClass += " adhoc";
			s += "<div class=\"sb-event-row" + stateClass + sel +
			     "\" data-uuid=\"" + san(e.uuid) + "\">";
			/* single line: when + tag + status + progress bar */
			s += "<span class=\"sb-event-when\">" + san(sai_sb_fmt_when(e.created)) +
			     " <span class='age-0' ut='" + e.created + "'>" +
			     agify(now_ut, e.created) + "</span></span>";
			s += "<span class=\"sb-event-tag\">" +
			     sai_weburl_link(e, "/log?id=" + encodeURIComponent(e.hash),
					     sai_event_hash_display(e.hash)) + "</span>";
			s += "<span class=\"sb-event-status\" id=\"sbsum-" + san(e.uuid) + "\"></span>";
			/* progress bar slot (inline, takes remaining width), filled by sai_sb_render_event_summary() */
			s += "<span class=\"sb-event-bar\" id=\"sbbar-" + san(e.uuid) + "\"></span>";
			s += "</div>";
		});
	}
	c.innerHTML = s;
	c.querySelectorAll(".sb-event-row").forEach(function(row) {
		row.addEventListener("click", function(ev) {
			/* embedded gitweb links navigate on their own */
			if (ev.target && ev.target.closest && ev.target.closest("a"))
				return;
			selectEvent(row.getAttribute("data-uuid"));
		});
	});

	/* Fill status text + progress bar for each visible event */
	matching.forEach(function(o) {
		sai_sb_render_event_summary(o.e.uuid);
	});
}

function selectSbProject(name)
{
	if (sb_selected_project === name)
		return;
	sb_selected_project = name;
	sb_selected_ref = null;
	/* clear the per-ref state map until the new project's branchlist arrives */
	sb_branch_states = {};
	render_sb_projects();
	/* refresh the branch list for this project; auto-selects newest branch */
	sai_sb_request_branches(name);
	/* move the tasks pane off the old project's event */
	sai_sb_follow_selection();
	sai_sb_update_url();
}

function selectSbBranch(ref)
{
	if (sb_selected_ref === ref)
		return;
	sb_selected_ref = ref;
	render_sb_branches();
	/* reflect the project + branch selection in the URL */
	sai_sb_update_url();
	/* re-scope the event list to the new selection */
	sai_sb_request_overview(0);
	/*
	 * Move the tasks pane to the most recent event on the new branch (or
	 * clear it until the scoped overview reply auto-selects it), so it
	 * doesn't keep showing the previous branch's event
	 */
	sai_sb_follow_selection();
	render_sb_events();
}

/*
 * The sidebar selection moved to a project / branch we hold no events for:
 * drop the stale event + task selection (and their URL params) so the tasks
 * pane stops showing an event from the old selection.  The scoped overview
 * reply auto-selects the newest matching event when it arrives.
 */
function sai_sb_clear_stale_selection()
{
	selected_event_uuid = null;
	clear_task_view();
	var c = document.getElementById("sai_event_tasks");
	if (c)
		c.innerHTML = "<div class=\"sb-empty\">No events</div>";
	var par = new URLSearchParams(window.location.search);
	par.delete("event");
	par.delete("task");
	par.delete("run");
	sai_update_history(par, true);
}

/*
 * Point the tasks pane at the most recent event matching the current sidebar
 * selection, so it never keeps showing an event from a different project /
 * branch.  If we hold no matching event yet, clear the stale selection until
 * the scoped overview reply auto-selects the newest one.
 */
function sai_sb_follow_selection()
{
	var newest = sai_sb_newest_matching_event();
	if (newest) {
		if (newest.e.uuid !== selected_event_uuid)
			selectEvent(newest.e.uuid);
		return;
	}
	if (selected_event_uuid)
		sai_sb_clear_stale_selection();
}

/*
 * Keep the project + branch in the URL query string so the view is shareable
 * and survives a reload.  Event/task params are managed by selectEvent; we
 * only touch project/branch here.
 */
function sai_sb_update_url()
{
	try {
		var par = new URLSearchParams(window.location.search);
		if (sb_selected_project)
			par.set("project", sb_selected_project);
		else
			par.delete("project");
		if (sb_selected_ref)
			par.set("branch", sb_selected_ref);
		else
			par.delete("branch");
		sai_update_history(par, true);
	} catch (e) {}
}

/*
 * Update the address bar with sai's shareable query params.  When sai is
 * embedded as a guest on another app's page (gitohashi integration), the URL
 * belongs to the host app -- we must not rewrite it with project=/branch=/
 * event=/task=/run=, or bare visits to the host page get polluted by sai's
 * sidebar auto-select cascade.
 *
 * \param par: a URLSearchParams holding the params to publish
 * \param replace: true -> replaceState (keep history clean for selection
 *        updates); false -> pushState (create a navigable entry for task/event
 *        deep links)
 */
function sai_update_history(par, replace)
{
	if (gitohashi_integ)
		return;

	var qs = par.toString();
	var path = window.location.pathname;
	if (!path.endsWith('/') && !path.endsWith('index.html'))
		path += '/';
	window.history[replace ? "replaceState" : "pushState"](
		{}, "", path + (qs ? ("?" + qs) : ""));
}

function render_event_decals() {
	/*
	 * The decal strip has been replaced by the merged 4-column sidebar
	 * pane.  Existing call sites still invoke this; just refresh col 4.
	 */
	render_sb_events();
}

/*
 * Event task table: the right-hand sub-pane of the tasks pane.
 *
 * One row per task (its latest run), coloured by the same taskstateN classes
 * as the sectionalized view on the left.  Clicking a column header makes it
 * the primary sort key; clicking it again flips the direction.  The choice
 * and the splitter position both persist in localStorage.
 *
 * Failed tasks always float to the top, above the user's sort order: once a
 * task has failed it isn't going to succeed, and what failed is always the
 * most interesting thing about an event.  Within the failed group, and again
 * within the rest, the user's sort order applies.
 */

var SAI_TT_SORT_LS = "sai-tasktable-sort";
var SAI_TT_SPLIT_LS = "sai-tasks-left-flex";
var sai_tt_sort = null; /* { key, dir } lazily loaded from localStorage */

var sai_tt_columns = [
	{ key: "taskname", label: "Task" },
	{ key: "platform", label: "Platform" },
	{ key: "started",  label: "Started" },
	{ key: "duration", label: "Duration" },
	{ key: "step",     label: "Step" }
];

/*
 * Rank for the "step" column: how far along the task is in its life, from
 * waiting through building to a final disposition
 */
function sai_tt_state_rank(state)
{
	switch (state) {
	case 8:  return 0; /* not ready */
	case 0:  return 1; /* waiting */
	case 1:  return 2; /* passed to builder */
	case 10: return 3; /* paused */
	case 2:  return 4; /* being built */
	case 6:  return 4; /* being built, has failures */
	case 3:  return 6; /* passed */
	case 4:  return 7; /* failed */
	case 5:  return 8; /* cancelled */
	case 11: return 8; /* yielded (idle task) */
	case 7:  return 9; /* deleted */
	}
	return 10;
}

function sai_tt_sort_get()
{
	if (sai_tt_sort)
		return sai_tt_sort;

	sai_tt_sort = { key: "taskname", dir: 1 };
	try {
		var j = JSON.parse(localStorage.getItem(SAI_TT_SORT_LS));
		if (j && sai_tt_columns.some(function(c) { return c.key === j.key; }))
			sai_tt_sort = { key: j.key, dir: j.dir < 0 ? -1 : 1 };
	} catch (e) {}

	return sai_tt_sort;
}

/* a column header was clicked: make it primary, or flip its direction */
function sai_tt_sort_click(key)
{
	var so = sai_tt_sort_get();

	if (so.key === key)
		so.dir = -so.dir;
	else {
		so.key = key;
		so.dir = 1;
	}
	try {
		localStorage.setItem(SAI_TT_SORT_LS, JSON.stringify(so));
	} catch (e) {}

	document.querySelectorAll("table.tt").forEach(function(tab) {
		sai_tt_mark_header(tab);
		sai_tt_resort(tab);
	});
}

function sai_tt_mark_header(tab)
{
	var so = sai_tt_sort_get();

	tab.querySelectorAll("th.tt-th").forEach(function(th) {
		th.classList.remove("sort-asc", "sort-desc");
		if (th.dataset.key === so.key)
			th.classList.add(so.dir > 0 ? "sort-asc" : "sort-desc");
	});
}

/*
 * Idle tasks ("lanes") only run in time builders would otherwise spend idle,
 * and aren't part of their event's result.  They're shown after the real
 * tasks, in their own group per task name.
 */
function sai_task_group_name(t)
{
	return (t.idle ? "idle: " : "") + t.taskname;
}

/* the event's tasks, real ones first, then the idle ones */
function sai_tasks_real_then_idle(tasks)
{
	return tasks.filter(function(t) { return !t.idle; }).concat(
	       tasks.filter(function(t) { return !!t.idle; }));
}

/* the latest run of each task uuid, keyed by uuid */
function sai_tt_latest_runs(tasks)
{
	var run_max = {};

	for (var q = 0; q < tasks.length; q++) {
		var tx = tasks[q];
		var ru = typeof tx.run !== 'undefined' ? tx.run : 0;
		var cur = run_max[tx.uuid];

		if (!cur || ru > (typeof cur.run !== 'undefined' ? cur.run : 0))
			run_max[tx.uuid] = tx;
	}

	return run_max;
}

function sai_tt_is_ongoing(state)
{
	return state === 1 || state === 2 || state === 6 || state === 10;
}

/*
 * Wallclock seconds the task has been building, or -1 if it never started.
 *
 * While it's still going, that's now minus the time the first step was
 * accepted (t.started, unix secs).  Once it reached a disposition, the
 * server stored the elapsed seconds at that moment in t.duration (see
 * sais_process_rej()); it also refreshes t.duration at each step boundary,
 * so it must not be preferred over the live clock for an ongoing task.
 */
function sai_tt_dur_secs(t, now_ut)
{
	if (t.started && sai_tt_is_ongoing(t.state))
		return Math.max(0, now_ut - t.started);
	if (t.duration)
		return t.duration;

	return -1;
}

function sai_tt_fmt_dur(secs)
{
	if (secs < 0)
		return "";

	secs = Math.round(secs);
	var h = Math.floor(secs / 3600),
	    m = Math.floor((secs % 3600) / 60),
	    sx = secs % 60;

	if (h)
		return h + "h " + m + "m " + sx + "s";
	if (m)
		return m + "m " + sx + "s";

	return sx + "s";
}

/* total step count as reported, or 0 if unknown */
function sai_tt_total_steps(t)
{
	var total = typeof t.total_steps !== 'undefined' ? t.total_steps :
							 t.build_step_count;

	return (typeof total !== 'undefined' && total > 0) ? total : 0;
}

/* text for the "Step" column: where the task is, or how it ended up */
function sai_tt_step_html(t)
{
	var total = sai_tt_total_steps(t);
	var have = total && typeof t.build_step !== 'undefined' && t.build_step >= 0;
	var at = have ? " at step " + (t.build_step + 1) + "/" + total : "";
	var s;

	switch (t.state) {
	case 0:  return "waiting";
	case 1:  return "assigned";
	case 2:
	case 6:
		s = have ? "step " + (t.build_step + 1) + "/" + total : "building";
		if (t.state === 6)
			s += " (failures)";
		if (have) {
			/* same percentage the left-hand view shades with */
			var pct = Math.round((t.build_step + 1) * 100 / (total + 2));
			pct = Math.min(100, Math.max(0, Math.round(pct / 5) * 5));
			s += "<span class=\"tt-bar\"><span class=\"w-" + pct +
			     "\"></span></span>";
		}
		return s;
	case 3:  return "passed";
	case 4:  return "failed" + at;
	case 5:  return "cancelled";
	case 7:  return "deleted";
	case 8:  return "not ready";
	case 10: return "paused" + at;
	case 11: return "yielded";
	}

	return "state " + t.state;
}

/*
 * Sort keys live on the row as data- attributes, so re-sorting after a live
 * state change is a pure DOM reorder and doesn't need the task list handy
 */
function sai_tt_row_keys(t)
{
	return {
		run:	 typeof t.run !== 'undefined' ? t.run : 0,
		state:	 t.state,
		name:	 sai_task_group_name(t),
		plat:	 t.platform,
		started: t.started ? t.started : 0,
		dur:	 t.duration ? t.duration : 0,
		step:	 (typeof t.build_step !== 'undefined' && t.build_step >= 0) ?
				t.build_step : -1
	};
}

function sai_tt_row_set_keys(tr, t)
{
	var k = sai_tt_row_keys(t);

	for (var n in k)
		tr.dataset[n] = k[n];
}

function sai_tt_row_html(t, e, now_ut)
{
	var s = "<tr id=\"tt_" + san(t.uuid) + "\" class=\"tt-row taskstate" + t.state +
		(t.idle ? " idle-lane" : "") +
		(t.uuid === selected_task_uuid ? " selected" : "") + "\"" +
		" data-task-uuid=\"" + san(t.uuid) + "\"" +
		" data-event-uuid=\"" + san(e.uuid) + "\"" +
		" data-platform=\"" + san(t.platform) + "\"" +
		" data-rebuildable=\"" + t.rebuildable + "\"";
	var k = sai_tt_row_keys(t);

	for (var n in k)
		s += " data-" + n + "=\"" + san(k[n]) + "\"";
	s += ">";

	s += "<td class=\"tt-name\">" + san(sai_task_group_name(t)) + "</td>";
	s += "<td class=\"tt-plat\">" + sai_plat_icon(t.platform, 0) + " " +
	     san(t.platform) + "</td>";
	s += "<td class=\"tt-started\">" +
	     (t.started ? agify(now_ut, t.started) + " ago" : "") + "</td>";
	s += "<td class=\"tt-dur tt-num\">" +
	     sai_tt_fmt_dur(sai_tt_dur_secs(t, now_ut)) + "</td>";
	s += "<td class=\"tt-step\">" + sai_tt_step_html(t) + "</td>";
	s += "</tr>";

	return s;
}

/*
 * Build the table HTML for an event's tasks.  Rows come out in task-list
 * order; the caller runs sai_tt_resort() once the table is in the DOM so
 * there's exactly one comparator.
 */
function sai_tt_render(o, now_ut)
{
	var so = sai_tt_sort_get();
	var s = "<table class=\"tt\" data-event-uuid=\"" + san(o.e.uuid) +
		"\"><thead><tr>";

	sai_tt_columns.forEach(function(c) {
		s += "<th class=\"tt-th" +
		     (c.key === so.key ? (so.dir > 0 ? " sort-asc" : " sort-desc") : "") +
		     "\" data-key=\"" + c.key + "\">" + c.label + "</th>";
	});
	s += "</tr></thead><tbody>";

	var latest = sai_tt_latest_runs(o.t);
	for (var u in latest)
		s += sai_tt_row_html(latest[u], o.e, now_ut);

	s += "</tbody></table>";

	return s;
}

/* the sortable value of a row for the given column, or null if it has none */
function sai_tt_row_key(tr, key, now_ut)
{
	var d = tr.dataset, state = parseInt(d.state);

	switch (key) {
	case "taskname":
		return d.name;
	case "platform":
		return d.plat;
	case "started":
		return parseInt(d.started) > 0 ? parseInt(d.started) : null;
	case "duration":
		if (parseInt(d.started) > 0 && sai_tt_is_ongoing(state))
			return now_ut - parseInt(d.started);
		if (parseInt(d.dur) > 0)
			return parseInt(d.dur);
		return null;
	case "step":
		return sai_tt_state_rank(state) * 10000 + (parseInt(d.step) + 1);
	}

	return null;
}

function sai_tt_cmp_vals(a, b)
{
	if (typeof a === "number" && typeof b === "number")
		return a - b;

	return String(a).localeCompare(String(b));
}

/*
 * Reorder the rows of a task table in place: failed first, then the user's
 * primary key and direction (rows lacking a value for it go last either
 * way), then task name and platform to keep the order stable.
 *
 * Sort keys are read once per row, and the DOM is only touched if the
 * order actually changed, in a single fragment append: this runs after
 * every live state change and on the duration tick, so it must be cheap
 * in the common no-op case.
 */
function sai_tt_resort(tab)
{
	var tbody = tab ? tab.tBodies[0] : null;
	if (!tbody)
		return;

	var so = sai_tt_sort_get();
	var now_ut = Math.round((new Date().getTime() / 1000));
	var cur = Array.prototype.slice.call(tbody.rows);
	var items = cur.map(function(tr) {
		return {
			tr:	tr,
			failed:	tr.dataset.state === "4" ? 0 : 1,
			key:	sai_tt_row_key(tr, so.key, now_ut),
			name:	tr.dataset.name,
			plat:	tr.dataset.plat
		};
	});

	items.sort(function(a, b) {
		if (a.failed !== b.failed)
			return a.failed - b.failed;

		if (a.key === null && b.key !== null)
			return 1;
		if (b.key === null && a.key !== null)
			return -1;
		if (a.key !== null) {
			var c = sai_tt_cmp_vals(a.key, b.key);
			if (c)
				return so.dir * c;
		}

		var c2 = sai_tt_cmp_vals(a.name, b.name);
		if (c2)
			return c2;

		return sai_tt_cmp_vals(a.plat, b.plat);
	});

	var moved = false;
	for (var i = 0; i < items.length; i++)
		if (items[i].tr !== cur[i]) {
			moved = true;
			break;
		}
	if (!moved)
		return;

	var frag = document.createDocumentFragment();
	items.forEach(function(it) { frag.appendChild(it.tr); });
	tbody.appendChild(frag);
}

/*
 * Coalesce re-sorts: a burst of task state broadcasts (or the per-task
 * refresh after a pane rebuild) asks many times, we sort once
 */
var sai_tt_resort_timer = null;

function sai_tt_schedule_resort()
{
	if (sai_tt_resort_timer)
		return;

	sai_tt_resort_timer = window.setTimeout(function() {
		sai_tt_resort_timer = null;
		document.querySelectorAll("table.tt").forEach(sai_tt_resort);
	}, 0);
}

/*
 * A task state broadcast arrived: update the matching row's colour, sort
 * keys and cells, then re-sort the table so it moves to where it belongs
 */
function sai_tt_refresh_row(t)
{
	var tr = document.getElementById("tt_" + t.uuid);
	if (!tr)
		return;

	/* the row tracks the latest run only; ignore news about older ones */
	var run = typeof t.run !== 'undefined' ? t.run : 0;
	if (run < parseInt(tr.dataset.run))
		return;

	/*
	 * Nothing to do if the row already reflects this task: the refresh
	 * pass after a pane rebuild hits every task, and the rows were just
	 * rendered from the same data
	 */
	var k = sai_tt_row_keys(t), changed = !tr.classList.contains("taskstate" + t.state) ||
					      tr.dataset.rebuildable !== String(t.rebuildable);
	for (var n in k)
		if (tr.dataset[n] !== String(k[n]))
			changed = true;
	if (!changed)
		return;

	var now_ut = Math.round((new Date().getTime() / 1000));
	var stale = [];

	for (var i = 0; i < tr.classList.length; i++)
		if (tr.classList[i].startsWith("taskstate"))
			stale.push(tr.classList[i]);
	stale.forEach(function(c) { tr.classList.remove(c); });
	tr.classList.add("taskstate" + t.state);

	sai_tt_row_set_keys(tr, t);
	tr.dataset.rebuildable = t.rebuildable;

	tr.cells[2].innerHTML = t.started ? agify(now_ut, t.started) + " ago" : "";
	tr.cells[3].textContent = sai_tt_fmt_dur(sai_tt_dur_secs(t, now_ut));
	tr.cells[4].innerHTML = sai_tt_step_html(t);

	sai_tt_schedule_resort();
}

/*
 * Periodic: keep the duration of ongoing tasks ticking, and if that's the
 * sort key, keep them in order too
 */
function sai_tt_tick()
{
	var rows = document.querySelectorAll("tr.tt-row");
	if (!rows.length)
		return;

	var now_ut = Math.round((new Date().getTime() / 1000));
	var live = 0;

	rows.forEach(function(tr) {
		var d = tr.dataset;

		if (!(parseInt(d.started) > 0) ||
		    !sai_tt_is_ongoing(parseInt(d.state)))
			return;

		var txt = sai_tt_fmt_dur(now_ut - parseInt(d.started));
		if (tr.cells[3].textContent !== txt)
			tr.cells[3].textContent = txt;
		live++;
	});

	if (live && sai_tt_sort_get().key === "duration")
		sai_tt_schedule_resort();
}

function sai_tt_set_selected(uuid)
{
	document.querySelectorAll("tr.tt-row").forEach(function(tr) {
		tr.classList.toggle("selected", !!uuid && tr.dataset.taskUuid === uuid);
	});
}

/* re-apply the remembered splitter position to a freshly rendered pane */
function sai_tt_apply_split()
{
	var l = document.getElementById("sai_tasks_left");
	if (!l)
		return;

	var f = null;
	try {
		f = localStorage.getItem(SAI_TT_SPLIT_LS);
	} catch (e) {}
	if (f)
		l.style.flex = f;
}

/*
 * Start dragging the splitter between the two task sub-panes.  The pane
 * markup is rebuilt on every event refresh, so this is driven from a
 * delegated mousedown / touchstart rather than a listener on the element.
 */
function sai_tt_split_begin(left, x0)
{
	var w0 = left.getBoundingClientRect().width;

	var apply = function(x) {
		var w = Math.round(w0 + (x - x0));
		if (w < 20)
			w = 0;
		/* shrinkable, so a remembered width wider than the pane can't hide the table */
		left.style.flex = "0 1 " + w + "px";
	};
	var finish = function() {
		document.removeEventListener('mousemove', mm);
		document.removeEventListener('mouseup', finish);
		document.removeEventListener('touchmove', tm);
		document.removeEventListener('touchend', finish);
		try {
			localStorage.setItem(SAI_TT_SPLIT_LS, left.style.flex);
		} catch (e) {}
	};
	var mm = function(e) { apply(e.clientX); };
	var tm = function(e) {
		if (e.touches.length === 1) {
			apply(e.touches[0].clientX);
			e.preventDefault();
		}
	};

	document.addEventListener('mousemove', mm);
	document.addEventListener('mouseup', finish);
	document.addEventListener('touchmove', tm, { passive: false });
	document.addEventListener('touchend', finish);
}

/*
 * Everything the tasks pane's markup depends on, flattened to a string, so
 * a rebuild can be skipped when an overview refresh brings nothing new.
 * Live per-task changes are applied in place by refresh_state(), so most
 * overview messages during a build change nothing here.
 */
var sai_tasks_pane_sig = null;

function sai_tasks_pane_signature(o)
{
	var e = o.e;
	var parts = [ e.uuid, e.state, e.adhoc ? 1 : 0, e.repo_name, e.ref,
		      e.hash, e.weburl || "", auth_state, gitohashi_integ ? 1 : 0 ];

	if (o.t)
		for (var q = 0; q < o.t.length; q++) {
			var t = o.t[q];

			parts.push(t.uuid, t.run, t.state, t.started, t.duration,
				   t.build_step, t.build_step_count, t.total_steps,
				   t.rebuildable, t.platform, t.taskname);
		}

	return parts.join("\x01");
}

function render_selected_event_tasks(o) {
	var now_ut = Math.round((new Date().getTime() / 1000));
	var s = "";
	var e = o.e;

	/*
	 * The tasks pane only makes sense once we have a context for it: either
	 * a sidebar project + branch selection, or an explicit deep-link
	 * (?event= / ?task=) that named a specific event/task.  Otherwise
	 * (initial page load, nothing chosen) leave it empty rather than
	 * showing tasks for an unrelated auto-selected event.
	 */
	var deep_link = false;
	try {
		var _p = new URLSearchParams(window.location.search);
		deep_link = !!(_p.get('event') || _p.get('task'));
	} catch (e2) {}

	if (!sb_selected_project && !sb_selected_ref && !deep_link) {
		var c = document.getElementById("sai_event_tasks");
		if (c)
			c.innerHTML = "<div class=\"sb-empty\">Select a project and branch</div>";
		sai_tasks_pane_sig = null;
		return;
	}

	/*
	 * Same event, same tasks, same header state as what's already in the
	 * pane (and nobody replaced the pane contents since): don't rebuild.
	 * Rebuilding recreates hundreds of platform icon <img>s and throws
	 * away the sub-panes' scroll positions for nothing.
	 */
	var sig = sai_tasks_pane_signature(o);
	var container = document.getElementById("sai_event_tasks");
	if (container && sig === sai_tasks_pane_sig &&
	    container.querySelector(".event-tasks-header[data-ev='" + san(e.uuid) + "']")) {
		update_summary_and_progress(e.uuid);
		return;
	}

	/*
	 * The header (title + admin restart-all / delete-event buttons) is
	 * always shown for the selected event, even when no task list is
	 * available yet (sidebar-scoped overview events arrive with t:[] and
	 * fetch their tasks on demand via selectEvent -> eventinfo).
	 */
	s += "<div data-ev=\"" + san(e.uuid) + "\" class=\"event-tasks-header";
	if (e.state == 3) s += " comp_pass";
	if (e.state == 4 || e.state == 6) s += " comp_fail";
	if (e.adhoc) s += " adhoc";
	s += "\">";
	var refName = e.ref.replace("refs/heads/", "").replace("refs/tags/", "");
	s += "<span class=\"event-tasks-title\">" +
	     sai_weburl_link(e, "", e.repo_name) +
	     " (" + sai_weburl_link(e, "/log?h=" + encodeURIComponent(refName), refName) + ")" +
	     " - " +
	     sai_weburl_link(e, "/log?id=" + encodeURIComponent(e.hash),
			     sai_event_hash_display(e.hash)) +
	     (e.adhoc ? " <span class=\"adhoc-tag\">ad-hoc</span>" : "") +
	     "</span>";
	/* admin-only restart-all / delete-event controls live here now */
	if (!gitohashi_integ && auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
		s += "<img class=\"rebuild\" alt=\"rebuild all\" src=\"/sai/rebuild.png\" " +
			"id=\"rebuild-ev-" + san(e.uuid) + "\">";
		s += "<img class=\"rebuild\" alt=\"delete event\" src=\"/sai/delete.png\" " +
			"id=\"delete-ev-" + san(e.uuid) + "\">";
	}
	s += "</div>";

	if (o.t && o.t.length) {
		/*
		 * Below the full-width header, two sub-panes with a draggable
		 * splitter: the sectionalized view on the left, the sortable
		 * task table on the right
		 */
		s += "<div class=\"tasks-split\">" +
		     "<div class=\"tasks-split-left\" id=\"sai_tasks_left\">";
		s += "<table class=\"tasks-table-display\"><tr><td class=\"tasks\" id=\"taskcont-" + san(e.uuid) + "\">";

		var run_max = {}, run_list = {};
		for (var q = 0; q < o.t.length; q++) {
			var tx = o.t[q];
			var ru = typeof tx.run !== 'undefined' ? tx.run : 0;
			if (!run_list[tx.uuid]) run_list[tx.uuid] = [];
			run_list[tx.uuid].push(tx);
			if (typeof run_max[tx.uuid] === 'undefined' || ru > (typeof run_max[tx.uuid].run !== 'undefined' ? run_max[tx.uuid].run : 0))
				run_max[tx.uuid] = tx;
		}
		for (var uid in run_list) {
			run_list[uid].sort(function(a, b) { var ar = typeof a.run !== 'undefined' ? a.run : 0; var br = typeof b.run !== 'undefined' ? b.run : 0; return ar - br; });
		}

		var ctn = "";
		var s1 = "";
		var ordered = sai_tasks_real_then_idle(o.t);
		for (var q = 0; q < ordered.length; q++) {
			var t = ordered[q];

			if (t !== run_max[t.uuid])
				continue;

			if (sai_task_group_name(t) !== ctn) {
				if (ctn !== "") {
					s += "<div class=\"ib\"><table class=\"nomar\">" +
					     "<tr><td class=\"tn\">" + hsanitize(ctn) +
					     "</td><td class=\"keepline\">" + s1 +
					     "</td></tr></table></div>";
					s1 = "";
				}
				ctn = sai_task_group_name(t);
			}

			s1 += "<div id=\"taskstate_" + t.uuid + "\" class=\"taskstate taskstate" + t.state +
				(t.idle ? " idle-lane" : "") +
				(run_list[t.uuid].length > 1 ? " has_runs" : "") +
				"\" data-task-uuid=\"" + san(t.uuid) +
				"\" data-event-uuid=\"" + san(e.uuid) + "\" data-platform=\"" + san(t.platform) +
				"\" data-rebuildable=\"" + t.rebuildable + "\">";
			s1 += "<a href=\"index.html?task=" + t.uuid + "\">" +
				sai_plat_icon(t.platform, 0) + "</a>";
			if (run_list[t.uuid].length > 1) {
				s1 += "<div class=\"runs-popup\"><table>";
				for (var w = 0; w < run_list[t.uuid].length; w++) {
					var rt = run_list[t.uuid][w];
					var rr = typeof rt.run !== 'undefined' ? rt.run : 0;
					var decal = "<div class=\"taskstate taskstate" + rt.state + " run-decal\"><a href=\"index.html?task=" + t.uuid + "&run=" + rr + "\">" + sai_plat_icon(rt.platform, 0) + "</a></div>";
					var timeStr = rt.started ? agify(now_ut, rt.started) + " ago" : "pending";
					s1 += "<tr><td>" + decal + "</td><td class=\"runs-time-cell\"><span class=\"ti5\">" + timeStr + "</span></td></tr>";
				}
				s1 += "</table></div>";
			}
			s1 += "</div>";
		}

		if (ctn !== "") {
			s += "<div class=\"ib\"><table class=\"nomar\">" +
				"<tr><td class=\"tn\">" + hsanitize(ctn) +
				"<td class=\"keepline\">" + s1 +
				"</td></tr></table></div>";
		}

		s += "</td></tr></table>";
		s += "</div>" +
		     "<div class=\"resizer-v\" id=\"resizer_tasks\"></div>" +
		     "<div class=\"tasks-split-right\" id=\"sai_tasks_right\">" +
		     sai_tt_render(o, now_ut) +
		     "</div></div>";
	} else {
		s += "<div class=\"no-tasks\">No tasks for this event</div>";
	}

	if (container) {
		sai_tasks_pane_sig = sig;
		/*
		 * The pane is rebuilt when its content changed; carry the
		 * sub-panes' scroll positions across so it doesn't jump
		 */
		var lp = document.getElementById("sai_tasks_left"),
		    rp = document.getElementById("sai_tasks_right");
		var l_top = lp ? lp.scrollTop : 0,
		    r_top = rp ? rp.scrollTop : 0,
		    r_left = rp ? rp.scrollLeft : 0;

		container.innerHTML = s;

		sai_tt_apply_split();
		sai_tt_resort(container.querySelector("table.tt"));

		lp = document.getElementById("sai_tasks_left");
		rp = document.getElementById("sai_tasks_right");
		if (lp)
			lp.scrollTop = l_top;
		if (rp) {
			rp.scrollTop = r_top;
			rp.scrollLeft = r_left;
		}

		// Refresh progress bars for these tasks
		if (o.t) {
			for (var q = 0; q < o.t.length; q++) {
				refresh_state(o.t[q]);
			}
		}
		update_summary_and_progress(e.uuid);
	}
}

/*
 * Drop the selected task and reset the task log view, eg because the
 * selected event changed to one that doesn't contain it.
 */
function clear_task_view()
{
	selected_task_uuid = null;
	window.current_task_run = null;
	sai_tt_set_selected(null);
	var stickyEl = document.getElementById("sai_sticky");
	var overviewEl = document.getElementById("sai_overview");
	if (stickyEl) stickyEl.innerHTML = "";
	if (overviewEl) overviewEl.innerHTML = "";

	sai_reset_log_pane(0);
}

function selectEvent(uuid) {
	selected_event_uuid = uuid;

	// Check if selected task belongs to this event
	var ev_obj = loaded_events.find(o => o.e.uuid === uuid);
	var hasTask = false;
	if (ev_obj && ev_obj.t && selected_task_uuid) {
		hasTask = ev_obj.t.some(t => t.uuid === selected_task_uuid);
	}
	if (!hasTask)
		clear_task_view();

	var par = new URLSearchParams(window.location.search);
	par.set("event", uuid);
	if (!hasTask) {
		par.delete("task");
		par.delete("run");
	}
	sai_update_history(par, false);

	// Highlight the selected event in the sidebar (col 4)
	var sbContainer = document.getElementById("sai_sb_events");
	if (sbContainer) {
		sbContainer.querySelectorAll(".sb-event-row").forEach(function(row) {
			if (row.getAttribute("data-uuid") === uuid) {
				row.classList.add("selected");
				row.scrollIntoView({ behavior: "smooth", block: "nearest" });
			} else {
				row.classList.remove("selected");
			}
		});
	}

	if (ev_obj) {
		render_selected_event_tasks(ev_obj);
		/* Notify server of the selected event so it can throttle task state broadcasts */
		sai.send("{\"schema\":\"com.warmcat.sai.eventinfo\", \"js_api_version\": " + SAI_JS_API_VERSION + ", \"event_hash\": " + JSON.stringify(uuid) + "}");
	}
}

/*
 * Throw away everything we are showing for a task's logs and start again from
 * the first row.  The task's rows can go away underneath us: "remove all tries"
 * deletes them, and a rebuild or a builder that dropped off starts a new run,
 * so sai-web tells us to do this rather than us appending new lines under stale
 * ones.  Pass 1 to rebuild the log DOM as well.
 */
function sai_reset_log_pane(rebuild_dom) {
	lines = times = logs = "";
	lines_pending = times_pending = logs_pending = "";
	segment_stack = [];
	seg_counter = 0;
	window.held_start_line = null;
	window.pending_log_line = "";
	logAnsiState = {};
	tfirst = 0;
	lli = 1;
	last_log_timestamp = 0;
	last_log_uid = 0;

	if (rebuild_dom) {
		init_task_logs_dom();
		return;
	}

	var dlogsn = document.getElementById("dlogsn");
	var dlogst = document.getElementById("dlogst");
	var dlogs = document.getElementById("dlogs");
	if (dlogsn) dlogsn.innerHTML = "";
	if (dlogst) dlogst.innerHTML = "";
	if (dlogs) dlogs.innerHTML = "<span id=\"logs\" class=\"nowrap\"></span>";
}

function init_task_logs_dom() {
	var s = "<table><td colspan=\"3\"><pre><table class=\"scrollogs\"><tr>" +
			"<td class=\"atop\">" +
			"<div id=\"dlogsn\" class=\"dlogsn\">" + lines + "</div></td>" +
			"<td class=\"atop\">" +
			"<div id=\"dlogst\" class=\"dlogst\">" + times + "</div></td>" +
			 "<td class=\"atop\"><div id=\"dlogs\" class=\"dlogs\">" +
			 "<span id=\"logs\" class=\"nowrap\">" + logs +
			 "</span>"+
			 "</div></td></tr></table></pre>";
	var overviewEl = document.getElementById("sai_overview");
	if (overviewEl) {
		overviewEl.innerHTML = s;
	}
}

function selectTask(taskUuid, runVal) {
	selected_task_uuid = taskUuid;
	window.current_task_run = runVal;
	sai_tt_set_selected(taskUuid);

	// Update URL query parameters dynamically (fully relative)
	var par = new URLSearchParams(window.location.search);
	par.set("task", taskUuid);
	if (runVal && runVal !== "-1") {
		par.set("run", runVal);
	} else {
		par.delete("run");
	}
	sai_update_history(par, false);

	// Setup loading state and clear logs (without the loading text overlay)
	var stickyEl = document.getElementById("sai_sticky");
	if (stickyEl) {
		stickyEl.innerHTML = "<div class=\"taskinfo\" id=\"taskinfo-" + san(taskUuid) + "\"></div>";
	}

	sai_reset_log_pane(1);

	// Request logs from websocket
	var req = "{\"schema\":" +
		  "\"com.warmcat.sai.taskinfo\"," +
		  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
		  "\"logs\": 1," +
		  "\"last_log_ts\":" + last_log_timestamp + ",\"last_log_uid\":" + last_log_uid + ",";
	if (runVal && runVal !== "-1")
		 req += "\"run\":" + runVal + ",";
	 else
		 req += "\"run\": -1,";
	req += "\"task_hash\":" + JSON.stringify(taskUuid) + "}";
	sai.send(req);
}

function sai_event_render(o, now_ut, reset_all_icon)
{
	var s, q, ctn = "", wai, s1 = "", n, e = o.e;

	s = "<tr><td class=\"waiting\"";
	if (gitohashi_integ)
		s += " id=\"gitohashi_sai_icon\"";
	s += "><div id=\"esr-" + san(e.uuid) + "\"></div></td>";

	if (o.t.length) {
		s += "<td class=\"tasks\" id=\"taskcont-" + san(e.uuid) + "\">";
		if (gitohashi_integ)
			s += "<div class=\"gi_popup\" id=\"gitohashi_sai_details\">";

		s += "<table><tr><td class=\"atop\">";

		var run_max = {}, run_list = {};
		for (q = 0; q < o.t.length; q++) {
			var tx = o.t[q];
			var ru = typeof tx.run !== 'undefined' ? tx.run : 0;
			if (!run_list[tx.uuid]) run_list[tx.uuid] = [];
			run_list[tx.uuid].push(tx);
			if (typeof run_max[tx.uuid] === 'undefined' || ru > (typeof run_max[tx.uuid].run !== 'undefined' ? run_max[tx.uuid].run : 0))
				run_max[tx.uuid] = tx;
		}
		for (var uid in run_list) {
			run_list[uid].sort(function(a, b) { var ar = typeof a.run !== 'undefined' ? a.run : 0; var br = typeof b.run !== 'undefined' ? b.run : 0; return ar - br; });
		}

		var ordered = sai_tasks_real_then_idle(o.t);
		for (q = 0; q < ordered.length; q++) {
			var t = ordered[q];

			if (t !== run_max[t.uuid])
				continue;

			if (sai_task_group_name(t) !== ctn) {
				if (ctn !== "") {
					s += "<div class=\"ib\"><table class=\"nomar\">" +
					     "<tr><td class=\"tn\">" + hsanitize(ctn) +
					     "</td><td class=\"keepline\">" + s1 +
					     "</td></tr></table></div>";
					s1 = "";
				}
				ctn = sai_task_group_name(t);
			}

			s1 += "<div id=\"taskstate_" + t.uuid + "\" class=\"taskstate taskstate" + t.state +
				(t.idle ? " idle-lane" : "") +
				(run_list[t.uuid].length > 1 ? " has_runs" : "") +
				"\" data-event-uuid=\"" + san(e.uuid) + "\" data-platform=\"" + san(t.platform) +
				"\" data-rebuildable=\"" + t.rebuildable + "\">";
			s1 += "<a href=\"/sai/index.html?task=" + t.uuid + "\">" +
				sai_plat_icon(t.platform, 0) + "</a>";
			if (run_list[t.uuid].length > 1) {
				s1 += "<div class=\"runs-popup\"><table>";
				for (var w = 0; w < run_list[t.uuid].length; w++) {
					var rt = run_list[t.uuid][w];
					var rr = typeof rt.run !== 'undefined' ? rt.run : 0;
					var decal = "<div class=\"taskstate taskstate" + rt.state + " run-decal\"><a href=\"/sai/index.html?task=" + t.uuid + "&run=" + rr + "\">" + sai_plat_icon(rt.platform, 0) + "</a></div>";
					var timeStr = rt.started ? agify(now_ut, rt.started) + " ago" : "pending";
					s1 += "<tr><td>" + decal + "</td><td class=\"runs-time-cell\"><span class=\"ti5\">" + timeStr + "</span></td></tr>";
				}
				s1 += "</table></div>";
			}
			s1 += "</div>";
		}

		if (ctn !== "") {
			s += "<div class=\"ib\"><table class=\"nomar\">" +
				"<tr><td class=\"tn\">" + hsanitize(ctn) +
				"<td class=\"keepline\">" + s1 +
				"</td></tr></table></div>";
		}

		s += "</td></tr></table>";
		if (gitohashi_integ)
			s += "</div>";
		s += "</td>";
	}

	s += "</tr>";

	return "<tbody id=\"ev-group-" + o.e.uuid + "\">" + s + "</tbody>";
}

function getBuilderHostname(platName) {
	return platName.split('.')[0];
}

function getBuilderGroupKey(platName) {
	let hostname = platName.split('.')[0];
	if (hostname.includes('-')) {
		let parts = hostname.split('-');
		return parts[parts.length - 1];
	}
	return hostname;
}

window.current_viewed_task_state = 0;

function check_and_apply_failure_ui() {
	if (window.current_viewed_task_state === 4 || window.current_viewed_task_state === 5 || window.current_viewed_task_state === 6) {
		var rootDlogs = document.getElementById("dlogs");
		if (rootDlogs) {
			var wrappers = rootDlogs.querySelectorAll(".log-segment-wrapper > .log-segment-header");
			/* Only want the top-level ones, which are direct children of #dlogs > .log-segment-wrapper */
			var topWrappers = [];
			for (var i = 0; i < wrappers.length; i++) {
				if (wrappers[i].parentElement && wrappers[i].parentElement.parentElement === rootDlogs) {
					topWrappers.push(wrappers[i]);
				}
			}
			if (topWrappers.length > 0) {
				var hdr = topWrappers[topWrappers.length - 1];
				hdr.classList.add("seg-fail-red");
				var body = hdr.nextElementSibling;
				if (body && body.classList.contains("hide")) {
					body.classList.remove("hide");
					var icon = hdr.querySelector('.fold-icon');
					if (icon) icon.innerText = "▼";
				}
			}
		}
	}
}

function refresh_state(t)
{
	var task_uuid = t.uuid;
	var task_state = t.state;
	var els = document.querySelectorAll("[id='taskstate_" + task_uuid + "']");

	els.forEach(function(tsi) {
		tsi.classList.remove("taskstate0");
		tsi.classList.remove("taskstate1");
		tsi.classList.remove("taskstate2");
		tsi.classList.remove("taskstate3");
		tsi.classList.remove("taskstate4");
		tsi.classList.remove("taskstate5");
		tsi.classList.remove("taskstate6");
		tsi.classList.remove("taskstate7");
		tsi.classList.remove("taskstate8");
		tsi.classList.remove("taskstate9");
		tsi.classList.remove("taskstate10");
		tsi.classList.remove("taskstate11");
		tsi.classList.add("taskstate" + task_state);

		var toRemove = [];
		for (var i = 0; i < tsi.classList.length; i++) {
			if (tsi.classList[i].startsWith('prog-')) {
				toRemove.push(tsi.classList[i]);
			}
		}
		toRemove.forEach(function(cls) { tsi.classList.remove(cls); });

		/*
		 * An idle task's slice isn't progress towards anything, it
		 * shows it's running differently (see .idle-lane in sai.css)
		 */
		if (!tsi.classList.contains("idle-lane") &&
		    (task_state === 1 || task_state === 2 || task_state === 6)) {
			var total = typeof t.total_steps !== 'undefined' ? t.total_steps : t.build_step_count;
			if (typeof t.build_step !== 'undefined' && typeof total !== 'undefined' && total >= 0) {
				var pct = Math.round((t.build_step + 1) * 100 / (total + 2));
				if (pct > 100) pct = 100;
				if (pct < 0) pct = 0;
				pct = Math.round(pct / 5) * 5;
				tsi.classList.add("prog-" + pct);
			}
		}
	});

	sai_tt_refresh_row(t);

	const urlParams = new URLSearchParams(window.location.search);
	const urlTask = urlParams.get('task');
	if (urlTask && urlTask === task_uuid) {
		window.current_viewed_task_state = task_state;
		check_and_apply_failure_ui();
	}
}



/*
 * Findings (admins only, see READMEs/README-findings.md)
 *
 * The fuzzing findings sai-server collected in the repos' pools, grouped into
 * bugs.  They can be unfixed security bugs, so sai-web only answers admins,
 * and nothing here is shown to anyone else.
 */

var sai_findings = null;	/* the last com.warmcat.sai.findings */
var sai_findings_dialog = null;
var sai_findings_timer = null;

var SAI_FINDINGS_STATUS = [ "open", "fixed", "won't fix" ];

function sai_findings_request()
{
	if (auth_state !== SaiAuthState.LOGGED_IN_GRANT_ADMIN)
		return;
	try {
		sai.send(JSON.stringify({ schema: "com.warmcat.sai.findings" }));
	} catch (e) {}
}

/* the admin state became known or changed */
function sai_findings_auth_changed()
{
	var btn = document.getElementById("sai_findings_btn");
	var admin = auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN;

	if (btn)
		btn.classList.toggle("hidden", !admin);

	if (!admin) {
		sai_findings = null;
		sai_findings_dialog_close();
		if (sai_findings_timer) {
			clearInterval(sai_findings_timer);
			sai_findings_timer = null;
		}
		return;
	}

	sai_findings_request();
	if (!sai_findings_timer)
		sai_findings_timer = setInterval(sai_findings_request, 60000);
}

function sai_findings_unacked()
{
	var n = 0;

	if (sai_findings && sai_findings.pools)
		sai_findings.pools.forEach(function(p) {
			p.groups.forEach(function(g) {
				if (!g.acked)
					n++;
			});
		});

	return n;
}

function sai_findings_update_button()
{
	var btn = document.getElementById("sai_findings_btn");
	var n = sai_findings_unacked();

	if (!btn)
		return;
	btn.textContent = n ? "findings: " + n + " new" : "findings";
	btn.classList.toggle("unacked", n > 0);
}

function sai_findings_dialog_close()
{
	if (!sai_findings_dialog)
		return;

	document.removeEventListener("keydown", sai_findings_dialog.onkey, true);
	if (document.body.contains(sai_findings_dialog.overlay))
		document.body.removeChild(sai_findings_dialog.overlay);
	sai_findings_dialog = null;
}

function sai_findings_set(p, g, op)
{
	sai.send(JSON.stringify({
		schema: "com.warmcat.sai.findingset",
		repo: p.repo, pool: p.pool, group: g.id, op: op
	}));
	/* sai-server applies it, then we look again */
	setTimeout(sai_findings_request, 500);
}

/* plain text, since it goes in textContent (agify() makes markup) */
function sai_findings_age(t)
{
	var d = Math.round((new Date().getTime() / 1000)) - t;

	if (!t)
		return "";
	if (d < 120)
		return d + "s ago";
	if (d < 7200)
		return Math.round(d / 60) + "m ago";
	if (d < 172800)
		return Math.round(d / 3600) + "h ago";

	return Math.round(d / 86400) + "d ago";
}

function sai_findings_group_row(p, g)
{
	var tr = sai_adhoc_el("tr", "findings-row" +
			      (g.acked ? "" : " unacked") +
			      (g.regressed ? " regressed" : "") +
			      " status" + g.status);
	var st = !g.acked ? (g.regressed ? "regressed" : "new") :
			    SAI_FINDINGS_STATUS[g.status] || "?";
	var td, b;

	tr.appendChild(sai_adhoc_el("td", "findings-status", st));
	tr.appendChild(sai_adhoc_el("td", "findings-id", g.id));
	tr.appendChild(sai_adhoc_el("td", "", g.sub));
	td = sai_adhoc_el("td", "findings-kind", g.kind);
	td.title = g.frames;
	tr.appendChild(td);
	tr.appendChild(sai_adhoc_el("td", "findings-frames", g.frames));
	tr.appendChild(sai_adhoc_el("td", "findings-num", String(g.hits)));
	td = sai_adhoc_el("td", "findings-seen", sai_findings_age(g.last_seen));
	td.title = "first " + g.first_hash.substring(0, 12) + " " +
		   sai_findings_age(g.first_seen) + ", last " +
		   g.last_hash.substring(0, 12) + "\non " + g.platforms;
	tr.appendChild(td);
	td = sai_adhoc_el("td", "findings-ok", g.last_ok_hash ?
			  "ok at " + g.last_ok_hash.substring(0, 12) : "");
	if (g.last_ok_hash)
		td.title = "its reproducer didn't crash at " + g.last_ok_hash +
			   ", " + sai_findings_age(g.last_ok_time);
	tr.appendChild(td);

	td = sai_adhoc_el("td", "findings-actions");
	var add = function(label, fn) {
		b = sai_adhoc_el("button", "sai-modal-button small", label);
		b.type = "button";
		b.addEventListener("click", fn);
		td.appendChild(b);
	};
	add("details", function() {
		sai.send(JSON.stringify({
			schema: "com.warmcat.sai.findingget",
			repo: p.repo, pool: p.pool, group: g.id, op: ""
		}));
	});
	if (!g.acked)
		add("ack", function() { sai_findings_set(p, g, "ack"); });
	if (g.status !== 1)
		add("fixed", function() { sai_findings_set(p, g, "fixed"); });
	if (g.status !== 2)
		add("won't fix", function() { sai_findings_set(p, g, "wontfix"); });
	if (g.status !== 0)
		add("reopen", function() { sai_findings_set(p, g, "reopen"); });
	tr.appendChild(td);

	return tr;
}

function sai_findings_render()
{
	var body, any = 0;

	if (!sai_findings_dialog)
		return;

	body = sai_findings_dialog.body;
	while (body.firstChild)
		body.removeChild(body.firstChild);

	if (sai_findings && sai_findings.pools)
		sai_findings.pools.forEach(function(p) {
			var tab, hr;

			if (!p.groups.length)
				return;
			any = 1;

			body.appendChild(sai_adhoc_el("div", "sai-modal-label",
						      p.repo + " / pool " + p.pool));
			tab = sai_adhoc_el("table", "findings-table");
			hr = sai_adhoc_el("tr");
			[ "", "group", "target", "kind", "where", "hits",
			  "last seen", "replay", "" ].forEach(function(h) {
				hr.appendChild(sai_adhoc_el("th", "", h));
			});
			tab.appendChild(hr);
			p.groups.forEach(function(g) {
				tab.appendChild(sai_findings_group_row(p, g));
			});
			body.appendChild(tab);
		});

	if (!any)
		body.appendChild(sai_adhoc_el("div", "sai-modal-sub",
					      "No findings"));
}

function sai_findings_dialog_open()
{
	sai_findings_dialog_close();

	var overlay = sai_adhoc_el("div", "sai-modal-overlay");
	var dlg = sai_adhoc_el("div", "sai-modal findings-modal");
	var body = sai_adhoc_el("div", "findings-body");
	var detail = sai_adhoc_el("div", "findings-detail hidden");

	dlg.appendChild(sai_adhoc_el("div", "sai-modal-title", "Findings"));
	dlg.appendChild(sai_adhoc_el("div", "sai-modal-sub",
		"Fuzzing findings in the repos' pools, grouped into bugs.  " +
		"These may be unfixed security bugs: admins only."));
	dlg.appendChild(body);
	dlg.appendChild(detail);

	var btns = sai_adhoc_el("div", "sai-modal-buttons");
	var close = sai_adhoc_el("button", "sai-modal-button", "Close");
	close.type = "button";
	close.addEventListener("click", sai_findings_dialog_close);
	btns.appendChild(close);
	dlg.appendChild(btns);

	overlay.appendChild(dlg);
	overlay.addEventListener("click", function(ev) {
		if (ev.target === overlay)
			sai_findings_dialog_close();
	});

	var onkey = function(ev) {
		if (ev.key === "Escape") {
			ev.preventDefault();
			sai_findings_dialog_close();
		}
	};
	document.addEventListener("keydown", onkey, true);

	sai_findings_dialog = { overlay: overlay, onkey: onkey, body: body,
				detail: detail };
	document.body.appendChild(overlay);

	sai_findings_render();
	sai_findings_request();
}

/* com.warmcat.sai.finding: one group's report and reproducer */
function sai_findings_show_detail(f)
{
	var d, pre, b;

	if (!sai_findings_dialog)
		return;

	d = sai_findings_dialog.detail;
	while (d.firstChild)
		d.removeChild(d.firstChild);
	d.classList.remove("hidden");

	d.appendChild(sai_adhoc_el("div", "sai-modal-label",
				   "Group " + f.group + ": " + f.name));

	if (f.repro) {
		b = sai_adhoc_el("button", "sai-modal-button small",
				 "download reproducer");
		b.type = "button";
		b.addEventListener("click", function() {
			var bin = atob(f.repro), u8 = new Uint8Array(bin.length);
			var a = document.createElement("a"), i;

			for (i = 0; i < bin.length; i++)
				u8[i] = bin.charCodeAt(i);
			a.href = URL.createObjectURL(new Blob([ u8 ],
				{ type: "application/octet-stream" }));
			a.download = f.name;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
		});
		d.appendChild(b);
	} else
		d.appendChild(sai_adhoc_el("div", "sai-modal-sub",
					   "The reproducer is too big to download here"));

	pre = sai_adhoc_el("pre", "findings-report", f.report || "(no report)");
	d.appendChild(pre);
}

/*
 * Ad-hoc build dialog
 *
 * Opened from the cloneinfo reply to the task context menu entry.  Lets the
 * admin pick which branch's head to build (defaulting to the most recently
 * pushed scratch "_" branch) and edit the build steps, then submits a
 * taskclone which sai-server turns into a new single-task event.
 *
 * The strict CSP forbids inline styles and scripts, so everything is built
 * with DOM calls and styled by classes in sai.css.
 */

/* keep under the 4096-byte array on the server side, with margin for UTF-8 */
const SAI_ADHOC_BUILD_MAXLEN = 4000;

var sai_adhoc_dialog = null;

function sai_adhoc_dialog_close()
{
	if (!sai_adhoc_dialog)
		return;

	document.removeEventListener("keydown", sai_adhoc_dialog.onkey, true);
	if (document.body.contains(sai_adhoc_dialog.overlay))
		document.body.removeChild(sai_adhoc_dialog.overlay);
	sai_adhoc_dialog = null;
}

function sai_adhoc_el(tag, cls, text)
{
	var el = document.createElement(tag);

	if (cls)
		el.className = cls;
	if (typeof text !== "undefined")
		el.textContent = text;

	return el;
}

/* "refs/heads/x" -> "x", tags and other refs left alone but shortened */
function sai_adhoc_ref_short(ref)
{
	if (ref.startsWith("refs/heads/"))
		return ref.substring(11);

	return ref;
}

/* accept "x" or "heads/x" as shorthand for "refs/heads/x" */
function sai_adhoc_ref_full(ref)
{
	ref = ref.trim();
	if (!ref.length)
		return "";
	if (ref.startsWith("refs/"))
		return ref;
	if (ref.startsWith("heads/") || ref.startsWith("tags/"))
		return "refs/" + ref;

	return "refs/heads/" + ref;
}

function sai_adhoc_dialog_open(info)
{
	sai_adhoc_dialog_close();

	var refs = info.refs || [];
	var overlay = sai_adhoc_el("div", "sai-modal-overlay");
	var dlg = sai_adhoc_el("div", "sai-modal");
	var listid = "sai-adhoc-refs";

	dlg.appendChild(sai_adhoc_el("div", "sai-modal-title",
				     "Ad-hoc build: " + info.taskname + " on " +
				     info.platform));
	dlg.appendChild(sai_adhoc_el("div", "sai-modal-sub",
				     info.repo_name + ", seeded from " +
				     sai_adhoc_ref_short(info.ref) + " task " +
				     info.seed_uuid.substring(32, 40)));

	/* branch to build the head of */

	var lab = sai_adhoc_el("label", "sai-modal-label", "Build head of branch");
	lab.htmlFor = "sai-adhoc-ref";
	dlg.appendChild(lab);

	var refrow = sai_adhoc_el("div", "sai-modal-row");
	var refin = sai_adhoc_el("input", "sai-modal-input");
	refin.type = "text";
	refin.id = "sai-adhoc-ref";
	refin.setAttribute("list", listid);
	refin.setAttribute("autocomplete", "off");
	refin.spellcheck = false;
	refin.placeholder = "refs/heads/_scratch";

	var dl = document.createElement("datalist");
	dl.id = listid;
	refs.forEach(function(r) {
		var opt = document.createElement("option");
		opt.value = r.ref;
		opt.label = sai_adhoc_ref_short(r.ref) + "  " +
			    r.hash.substring(0, 8);
		dl.appendChild(opt);
	});
	refrow.appendChild(refin);
	refrow.appendChild(dl);

	var hashnote = sai_adhoc_el("div", "sai-modal-hash", "");
	refrow.appendChild(hashnote);
	dlg.appendChild(refrow);

	/* the server resolves the ref itself; this is just a preview */
	var update_hash = function() {
		var full = sai_adhoc_ref_full(refin.value);
		var m = refs.find(function(r) { return r.ref === full; });

		if (m)
			hashnote.textContent = "last pushed: " + m.hash;
		else if (full === info.ref)
			hashnote.textContent = "same branch as the seed task";
		else
			hashnote.textContent = "not a scratch branch: sai-server " +
					       "uses the newest hash it was " +
					       "notified of for this branch";
	};
	refin.addEventListener("input", update_hash);

	/*
	 * Default to the most recently pushed scratch branch, else the seed's
	 * own branch
	 */
	refin.value = refs.length ? refs[0].ref : info.ref;
	update_hash();

	/* build steps */

	lab = sai_adhoc_el("label", "sai-modal-label", "Build steps (one per line)");
	lab.htmlFor = "sai-adhoc-build";
	dlg.appendChild(lab);

	var ta = sai_adhoc_el("textarea", "sai-modal-textarea");
	ta.id = "sai-adhoc-build";
	ta.spellcheck = false;
	ta.maxLength = SAI_ADHOC_BUILD_MAXLEN;
	ta.value = info.build || "";
	dlg.appendChild(ta);

	var counter = sai_adhoc_el("div", "sai-modal-note", "");
	var update_counter = function() {
		var n = new TextEncoder().encode(ta.value).length;

		counter.textContent = n + " / " + SAI_ADHOC_BUILD_MAXLEN + " bytes";
		counter.classList.toggle("over", n > SAI_ADHOC_BUILD_MAXLEN);
	};
	ta.addEventListener("input", update_counter);
	update_counter();
	dlg.appendChild(counter);

	var errline = sai_adhoc_el("div", "sai-modal-error", "");
	dlg.appendChild(errline);

	/* buttons */

	var btns = sai_adhoc_el("div", "sai-modal-buttons");
	var cancel = sai_adhoc_el("button", "sai-modal-button", "Cancel");
	cancel.type = "button";
	cancel.addEventListener("click", sai_adhoc_dialog_close);
	var go = sai_adhoc_el("button", "sai-modal-button primary", "Schedule");
	go.type = "button";
	go.addEventListener("click", function() {
		var ref = sai_adhoc_ref_full(refin.value);
		var build = ta.value;

		if (!ref.length || !/^refs\/[A-Za-z0-9_.\/-]+$/.test(ref) ||
		    ref.indexOf("..") !== -1) {
			errline.textContent = "Branch must be a plain ref name like refs/heads/_scratch";
			return;
		}
		if (!build.trim().length) {
			errline.textContent = "Build steps can't be empty";
			return;
		}
		if (new TextEncoder().encode(build).length > SAI_ADHOC_BUILD_MAXLEN) {
			errline.textContent = "Build steps too long";
			return;
		}

		sai.send(JSON.stringify({
			schema: "com.warmcat.sai.taskclone",
			seed_uuid: info.seed_uuid,
			ref: ref,
			build: build
		}));
		sai_adhoc_dialog_close();
	});
	btns.appendChild(cancel);
	btns.appendChild(go);
	dlg.appendChild(btns);

	overlay.appendChild(dlg);
	overlay.addEventListener("click", function(ev) {
		if (ev.target === overlay)
			sai_adhoc_dialog_close();
	});

	var onkey = function(ev) {
		if (ev.key === "Escape") {
			ev.preventDefault();
			sai_adhoc_dialog_close();
		}
	};
	document.addEventListener("keydown", onkey, true);

	sai_adhoc_dialog = { overlay: overlay, onkey: onkey };
	document.body.appendChild(overlay);
	refin.focus();
}

function createContextMenu(event, menuItems) {
    event.preventDefault();

    // Remove any existing context menu
    const existingMenus = document.querySelectorAll(".context-menu");
    existingMenus.forEach(menu => {
        if (document.body.contains(menu))
            document.body.removeChild(menu);
    });

    const menu = document.createElement("div");
    menu.className = "context-menu";
    menu.style.top = event.pageY + "px";
    menu.style.left = event.pageX + "px";

    const ul = document.createElement("ul");
    menu.appendChild(ul);

    /*
     * We have to do this via a function because the event listener
     * for the global click needs to be removable, but the click
     * handler for the menu items also wants to use it.
     */
    const closeMenu = () => {
        if (document.body.contains(menu)) {
            document.body.removeChild(menu);
        }
        window.removeEventListener("click", closeMenu, true);
    };

    menuItems.forEach(item => {
        const li = document.createElement("li");
        li.innerHTML = item.label;
        if (item.callback) {
            li.addEventListener("click", (e) => {
                item.callback(e);
                closeMenu();
            });
        } else {
            li.classList.add("read-only");
        }
        ul.appendChild(li);
    });

    document.body.appendChild(menu);

    /*
     * Now we have the content, we can see how big it is.  If it
     * is going off the right of the page, move it left so it ends
     * at the click coordinates.
     */

    const rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth)
         menu.style.left = (event.pageX - rect.width) + "px";

    /*
     * defer adding the click listener so the current click
     * doesn't trigger it.  Use capture on window so we get
     * it even if the click target stops propagation.
     */
    setTimeout(() => {
        window.addEventListener("click", closeMenu, true);
    }, 0);
}

function createBuilderDiv(plat) {
	const platDiv = document.createElement("div");
	platDiv.className = "ibuil bdr";
	if (plat.name.startsWith("sai-vm-")) {
		platDiv.className += " vm-builder";
	}
	if (!plat.online)
		platDiv.className += " offline";
	else {
		if (!plat.power_managed)
			platDiv.className += " power-unmanaged";
		else {
			let pcon = pcon_topology[plat.pcon];
			if (pcon && pcon.manual_on)
				platDiv.className += " power-stay";
			else
				platDiv.className += " power-stay-dep";
		}
	}
	if (plat.powering_up)
		platDiv.className += " powering-up";
	if (plat.powering_down)
		platDiv.className += " powering-down";

	platDiv.id = "binfo-" + plat.name;
	platDiv.title = plat.platform + "@" + plat.name.split('.')[0] + (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN && plat.peer_ip ? " / " + plat.peer_ip : "");

	let plat_parts = plat.platform.split('/');
	let plat_os = plat_parts[0] || 'generic';
	let plat_arch = plat_parts[1] || 'generic';
	let plat_tc = plat_parts[2] || 'generic';
	let short_name = plat.name.split('.')[0];

	let innerHTML = `<table class="nomar"><tbody><tr><td class="bn">`;
	innerHTML += `<div class="builder-name-row">` +
		     `<div class="builder-short-name">${hsanitize(short_name)}</div>` +
		     `<div class="builder-icons">` +
		     `<img class="ip1 zup" data-sai-src="/sai/${plat_os}.svg">` +
		     `<img class="ip1 tread1" data-sai-src="/sai/arch-${plat_arch}.svg">` +
		     `<img class="ip1 tread2" data-sai-src="/sai/tc-${plat_tc}.svg">` +
		     `</div></div>`;
	innerHTML += `<div class="resource-bars">` +
		     `<div class="res-bar"><div class="res-bar-inner res-bar-cpu w-0"></div></div>` +
		     `<div class="res-bar"><div class="res-bar-inner res-bar-ram w-0"></div></div>` +
		     `<div class="res-bar"><div class="res-bar-inner res-bar-disk w-0"></div></div>` +
		     `</div>`;
	if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN && plat.peer_ip)
		innerHTML += `<div class="plat-peer-ip">${hsanitize(plat.peer_ip)}</div>`;
	innerHTML +=  `</td></tr></tbody></table>`;

	platDiv.innerHTML = innerHTML;

	const images = platDiv.querySelectorAll('img[data-sai-src]');
	images.forEach(img => {
		img.onerror = () => {
			img.src = '/sai/generic.svg';
			img.onerror = null; // prevent infinite loops
		};
		img.src = img.getAttribute('data-sai-src');
	});

	const menuItems = [
		{ label: `<b>SAI:</b> ${san(plat.sai_hash)}` },
		{ label: `<b>LWS:</b> ${san(plat.lws_hash)}` },
	];

	if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN && !plat.online) {
		menuItems.push({
			label: "<span class='builder-delete-btn'>Delete Builder</span>",
			callback: () => {
				if (confirm("Are you sure you want to delete builder " + plat.name + "?")) {
					const msg = {
						schema: "com.warmcat.sai.builderdelete",
						builder_name: plat.name
					};
					sai.send(JSON.stringify(msg));
				}
			}
		});
	}

	if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
		menuItems.push({
			label: "<span class='builder-shell-btn'>Open Shell</span>",
			callback: () => {
				/* 16 random bytes -> 32 hex chars: the shell id shape
				 * the server validates (SAI_SHELLID_LEN) */
				const task_uuid = Array.from(crypto.getRandomValues(new Uint8Array(16)))
					.map(b => b.toString(16).padStart(2, '0')).join('');

				const msg = {
					schema: "com.warmcat.sai.openshell",
					builder_name: plat.name,
					task_uuid: task_uuid
				};
				sai.send(JSON.stringify(msg));

				const term = new SaiTerminal(document.body, {
					title: "Terminal: " + plat.name,
					platform: plat.platform,
					onData: (data) => {
						const ptyMsg = {
							schema: "com.warmcat.sai.ptydata",
							builder_name: plat.name,
							task_uuid: task_uuid,
							channel: 0,
							data: btoa(data),
							len: data.length
						};
						sai.send(JSON.stringify(ptyMsg));
					},
					onResize: (cols, rows) => {
						const resizeMsg = {
							schema: "com.warmcat.sai.ptydata",
							builder_name: plat.name,
							task_uuid: task_uuid,
							channel: 0,
							cols: cols,
							rows: rows,
							data: "",
							len: 0
						};
						sai.send(JSON.stringify(resizeMsg));
					},
					onClose: () => {
						const closeMsg = {
							schema: "com.warmcat.sai.closeshell",
							task_uuid: task_uuid
						};
						sai.send(JSON.stringify(closeMsg));
						delete active_terminals[task_uuid];
					}
				});
				active_terminals[task_uuid] = term;
			}
		});
	}

	platDiv.addEventListener("contextmenu", function(event) {
		if (!authd)
			return;
		createContextMenu(event, menuItems);
	});

    let touchStartTime = 0;
    let touchStartPos = { x: 0, y: 0 };

    platDiv.addEventListener("touchstart", function(event) {
        if (event.touches.length > 1) {
            return;
        }
        touchStartTime = Date.now();
        const touch = event.touches[0];
        touchStartPos = { x: touch.pageX, y: touch.pageY };
    });

    platDiv.addEventListener("touchend", function(event) {
        const touchEndTime = Date.now();
        const touch = event.changedTouches[0];
        const touchEndPos = { x: touch.pageX, y: touch.pageY };
        const pressDuration = touchEndTime - touchStartTime;
        const distance = Math.sqrt(
            Math.pow(touchEndPos.x - touchStartPos.x, 2) +
            Math.pow(touchEndPos.y - touchStartPos.y, 2)
        );

        if (pressDuration >= 500 && distance < 10) {
            event.preventDefault();

            const mockEvent = {
                preventDefault: () => {},
                pageX: touchStartPos.x,
                pageY: touchStartPos.y
            };
            if (authd)
		createContextMenu(mockEvent, menuItems);
        }
        touchStartTime = 0;
    });

	return platDiv;
}

function updateSpreadsheetCell(cell, platName) {
	let best_match_key = null;
	for (const short_name in spreadsheet_data_cache) {
		if (platName.startsWith(short_name)) {
			if (!best_match_key || short_name.length > best_match_key.length) {
				best_match_key = short_name;
			}
		}
	}

	if (best_match_key) {
		updateSpreadsheetDOM(cell, spreadsheet_data_cache[best_match_key]);
		aging();
	} else {
		cell.innerHTML = ""; // Clear it if no data
	}
}

function createBuilderRow(plat) {
	const tr = document.createElement("tr");
	tr.id = "row-" + plat.name;

	const tdInfo = document.createElement("td");
	tdInfo.className = "builder-info";
	const builderDiv = createBuilderDiv(plat);
	tdInfo.appendChild(builderDiv);
	tr.appendChild(tdInfo);

	const tdSpreadsheet = document.createElement("td");
	tdSpreadsheet.className = "spreadsheet-container";
	tdSpreadsheet.id = "spreadsheet-" + plat.name;
	updateSpreadsheetCell(tdSpreadsheet, plat.name);
	tr.appendChild(tdSpreadsheet);

	return tr;
}

function updateBuilderRow(row, plat) {
	const tdInfo = row.querySelector(".builder-info");
	const tdSpreadsheet = row.querySelector(".spreadsheet-container");

	// Update builder info div
	// This is simple enough that a full replacement is fine and ensures listeners are correct.
	tdInfo.innerHTML = "";
	tdInfo.appendChild(createBuilderDiv(plat));

	// Update spreadsheet view for this builder
	updateSpreadsheetCell(tdSpreadsheet, plat.name);
}

/* Global caches for reconcilation */
var pcon_topology = {};
var last_builder_list = [];

function createPconDiv(pcon) {
    const pconDiv = document.createElement("div");
    pconDiv.className = "pcon";
    pconDiv.id = "pcon-" + pcon.name;
    pconDiv.style.marginLeft = "10px";
    pconDiv.style.borderLeft = "1px solid #ccc";
    pconDiv.style.paddingLeft = "5px";

    const header = document.createElement("div");
    header.className = "pcon-header";

    const myBuilders = last_builder_list.filter(b => b.pcon === pcon.name);
    let anyConnected = myBuilders.some(b => b.online === 1);
    let anyPoweringUp = myBuilders.some(b => b.powering_up === 1);

    let isActuallyOn = false;
    let stateClass = "pcon-off";

    if (pcon_energy_cache[pcon.name]) {
        const d = pcon_energy_cache[pcon.name];
        let hasPower = d.voltage_v >= 70 && d.active_power_w > 0;
        isActuallyOn = anyConnected || anyPoweringUp || hasPower;
        stateClass = hasPower ? "pcon-on" : "pcon-off";
    } else {
        isActuallyOn = anyConnected || (pcon.on === 1 && !anyPoweringUp);
        stateClass = (pcon.on === 1) ? "pcon-on" : "pcon-off";
    }

    if (isActuallyOn) {
        header.className += " pcon-header-on";
    }

    let type = pcon.type ? `(${pcon.type})` : "";

    header.innerHTML = `<span class="${stateClass}">&#x23FB;</span> <b>${hsanitize(pcon.name)}</b> <span class="pcon-type">${hsanitize(type)}</span>`;

    if (pcon_energy_cache[pcon.name]) {
        const d = pcon_energy_cache[pcon.name];
        let stats = document.createElement("span");
        stats.className = "pcon-stats";
        stats.style.marginLeft = "10px";
        stats.style.fontSize = "0.9em";
        stats.style.color = "#666";
	if (d.voltage_v < 70)
		stats.textContent = "unpowered";
	else if (!d.active_power_w)
		stats.textContent = "OFF";
	else
		stats.textContent = `${d.active_power_w}W`;

        header.appendChild(stats);
    }

    pconDiv.appendChild(header);

    /* Context menu for PCON */
    const menuItems = [
        { label: `<b>PCON:</b> ${san(pcon.name)}` }
    ];

    if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
        if (isActuallyOn) {
            menuItems.push({
                label: "Turn Off",
                callback: () => {
                    const msg = {
                        schema: "com.warmcat.sai.pcon_control",
                        pcon_name: pcon.name,
                        on: 0
                    };
                    sai.send(JSON.stringify(msg));
                }
            });
        } else {
             menuItems.push({
                label: "Turn On",
                callback: () => {
                    const msg = {
                        schema: "com.warmcat.sai.pcon_control",
                        pcon_name: pcon.name,
                        on: 1
                    };
                    sai.send(JSON.stringify(msg));
                }
            });
        }
    }

    header.addEventListener("contextmenu", function(event) {
        if (!authd) return;
        createContextMenu(event, menuItems);
    });

    const childrenDiv = document.createElement("div");
    childrenDiv.className = "pcon-children";
    pconDiv.appendChild(childrenDiv);

    return pconDiv;
}

let last_renderPconHierarchy_state = "";

function renderPconHierarchy(container) {
    if (!container) return;

    const builders_no_time = last_builder_list.map(b => {
        const { last_seen, ...rest } = b;
        return rest;
    });

    const clean_pcons = {};
    for (const [k, p] of Object.entries(pcon_topology)) {
        const { children, ...rest } = p;
        clean_pcons[k] = rest;
    }

    /* Serialize the inputs to quickly see if we actually need to redraw everything */
    const currentState = JSON.stringify({
        pcons: clean_pcons,
        builders: builders_no_time
    });

    if (currentState === last_renderPconHierarchy_state) {
        return;
    }
    last_renderPconHierarchy_state = currentState;

    /* Clear and redraw for now to ensure structure is correct */
    container.innerHTML = "";

    const pcons = Object.values(pcon_topology);
    /* Build map for dependency resolution */
    const pconMap = {};
    pcons.forEach(p => {
        p.children = []; /* Reset children */
        pconMap[p.name] = p;
    });

    /* Link PCONs */
    const roots = [];
    pcons.forEach(p => {
        if (p.depends_on && pconMap[p.depends_on]) {
            pconMap[p.depends_on].children.push(p);
        } else {
            roots.push(p);
        }
    });

    /* Sort roots and children by name */
    const sortByName = (a, b) => a.name.localeCompare(b.name);
    roots.sort(sortByName);
    pcons.forEach(p => p.children.sort(sortByName));

    const appendBuilderRows = (buildersList, tbody) => {
        let prevBaseName = null;
        let prevTr = null;
        let stackedCount = 0;

        buildersList.forEach(b => {
            let baseName = b.name.split('.')[0].replace(/-\d+$/, '');
            if (!b.online && baseName === prevBaseName && prevTr) {
                stackedCount++;
                const tdInfo = prevTr.querySelector(".builder-info");
                const builderDiv = createBuilderDiv(b);
                
                /* Stacking visual effect */
                builderDiv.style.position = "absolute";
                builderDiv.style.top = (stackedCount * 6) + "px";
                builderDiv.style.left = (stackedCount * 6) + "px";
                builderDiv.style.zIndex = 10 - stackedCount;
                builderDiv.style.boxShadow = "-2px -2px 4px rgba(0,0,0,0.15)";
                
                tdInfo.style.position = "relative";
                tdInfo.style.paddingBottom = (stackedCount * 6) + "px";
                tdInfo.style.paddingRight = (stackedCount * 6) + "px";

                tdInfo.appendChild(builderDiv);
            } else {
                const tr = createBuilderRow(b);
                tbody.appendChild(tr);
                prevTr = tr;
                prevBaseName = baseName;
                stackedCount = 0;

                const builderDiv = tr.querySelector(".builder-info .ibuil");
                if (builderDiv) {
                    builderDiv.style.position = "relative";
                    builderDiv.style.zIndex = 10;
                }
            }
        });
    };

    /* Helper to recursively render PCONs and their builders */
    function renderPcon(pcon, parentDiv) {
        const div = createPconDiv(pcon);
        parentDiv.appendChild(div);
        const childrenContainer = div.querySelector(".pcon-children");

        /* Render builders belonging to this PCON */
        /* We search the global builder list for those matching this pcon */
        const myBuilders = last_builder_list.filter(b => b.pcon === pcon.name);
        myBuilders.sort((a, b) => a.name.localeCompare(b.name));

        if (myBuilders.length > 0) {
            const table = document.createElement("table");
            table.className = "builders";
            const tbody = document.createElement("tbody");
            table.appendChild(tbody);
            appendBuilderRows(myBuilders, tbody);
            childrenContainer.appendChild(table);
        }

        /* Render child PCONs */
        pcon.children.forEach(child => {
            renderPcon(child, childrenContainer);
        });
    }

    roots.forEach(root => {
        renderPcon(root, container);
    });

    /* Render orphan builders (no pcon or unknown pcon) */
    const orphanBuilders = last_builder_list.filter(b => !b.pcon || !pcon_topology[b.pcon]);
    if (orphanBuilders.length > 0) {
        const orphanDiv = document.createElement("div");
        orphanDiv.className = "pcon-orphans";
        orphanDiv.innerHTML = "<div class='pcon-header'><b>Unmanaged Builders</b></div>";
        const childrenContainer = document.createElement("div");
        childrenContainer.className = "pcon-children";
        orphanDiv.appendChild(childrenContainer);

        const table = document.createElement("table");
        table.className = "builders";
        const tbody = document.createElement("tbody");
        table.appendChild(tbody);
        appendBuilderRows(orphanBuilders, tbody);
        childrenContainer.appendChild(table);

        container.appendChild(orphanDiv);
    }
}

let sai_power_samples = [];
let sai_max_total_power_w = 0;

function updatePowerGraph(total_w) {
    const overviewDiv = document.getElementById("sai_power_overview");
    const powerText = document.getElementById("sai_total_power");
    const canvas = document.getElementById("sai_power_graph");

    if (!overviewDiv || !powerText || !canvas) return;

    if (overviewDiv.classList.contains("hidden")) {
        overviewDiv.classList.remove("hidden");
    }

    /* if no updates passed (just drawing from memory), avoid adding a new sample */
    if (total_w !== null) {
        powerText.textContent = total_w + "W";

        if (total_w > sai_max_total_power_w) {
            sai_max_total_power_w = total_w;
        }

        sai_power_samples.push(total_w);
    } else {
        if (sai_power_samples.length > 0)
             powerText.textContent = sai_power_samples[sai_power_samples.length - 1] + "W";
    }

    const ctx = canvas.getContext("2d");
    if (canvas.width !== canvas.clientWidth) {
        canvas.width = canvas.clientWidth;
    }

    const w = canvas.width;
    const h = canvas.height;

    if (sai_power_samples.length > w) {
        sai_power_samples.shift();
    }

    ctx.clearRect(0, 0, w, h);
    if (sai_power_samples.length === 0) return;

    const max_y = sai_max_total_power_w > 0 ? sai_max_total_power_w : 1;

    ctx.fillStyle = "#ff4136";
    const startX = w - sai_power_samples.length;

    for (let i = 0; i < sai_power_samples.length; i++) {
        const val = sai_power_samples[i];
        const barH = (val / max_y) * h;
        ctx.fillRect(startX + i, h - barH, 1, barH);
    }
}

function ws_open_sai()
{
	var s = "", q, qa, qi, q5, q5s;

	if (document.getElementById("apirev"))
		document.getElementById("apirev").innerHTML = "API rev " + SAI_JS_API_VERSION;

	q = window.location.href;
	console.log(q);
	qi = q.indexOf("/git/");
	if (qi !== -1) {
		/* it has the /git/... does it have the project? */
		s += "/specific";
		q5 = q.substring(qi + 5);
		console.log("q5 = " + q5);
		q5s = q5.indexOf("/");
		if (q5s !== -1)
			s += "/" + q5.substring(0, q5s);
		else
			s += "/" + q5;

		/*
		 * gitohashi has ?h=branch and ?id=hash possible
		 */
		qa = q.split("?");
		if (qa[1])
			s += "?" + qa[1];
		console.log(s);
		gitohashi_integ = 1;
	}

	qi = q.indexOf("?task=");
	if (qi != -1) {
		/*
		 * it's a sai task details page
		 */
		s += "/specific?task=" + q.substring(qi + 6);
	}

	var s1 = get_appropriate_ws_url() + "/sai/browse" + s;
	if (typeof gitohashi_integ === 'undefined' || !gitohashi_integ) {
		if (s1.indexOf('?') !== -1)
			s1 += "&client=sai";
		else
			s1 += "?client=sai";
	}
//	if (s1.split("?"))
//	s1 = s1.split("?")[0];
	console.log(s1);
	sai = new WebSocket(s1, "com-warmcat-sai");
	try {

		sai.onopen = function() {
			if (typeof window.overlayTimeout !== 'undefined' && window.overlayTimeout) {
				clearTimeout(window.overlayTimeout);
				window.overlayTimeout = null;
			}
			var overlay = document.querySelector(".overlay");
			if (overlay) {
				overlay.parentNode.removeChild(overlay);
			}
			document.body.classList.remove("overlay-active");

			let savedRightPaneFlex = localStorage.getItem('sai-right-pane-flex');
			let initialVisible = 0;
			if (savedRightPaneFlex && parseInt(savedRightPaneFlex.replace(/[^0-9-]/g, '')) > 0) {
				initialVisible = 1;
			}
			sai.send(JSON.stringify({ schema: "com.warmcat.sai.builder_visibility", visible: initialVisible }));

			var par = new URLSearchParams(window.location.search),
				tid, eid, run_idx;
			tid = par.get('task');
			eid = par.get('event');
			run_idx = par.get('run');

			if (tid) {
				 console.log("tid " + tid);
				 selected_task_uuid = tid;
				 if (run_idx) window.current_task_run = run_idx;

				 var req = "{\"schema\":" +
					  "\"com.warmcat.sai.taskinfo\"," +
					  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
					  "\"logs\": 1," +
					  "\"last_log_ts\":" + last_log_timestamp + ",\"last_log_uid\":" + last_log_uid + ",";
				 if (run_idx)
					 req += "\"run\":" + run_idx + ",";
				 else
					 req += "\"run\": -1,";
					 req += "\"task_hash\":" + JSON.stringify(tid) + "}";
					 sai.send(req);

					 // Also request the overview (unscoped, so the
					 // deep-linked task's event is included)
					 sai.send("{\"schema\":" +
						  "\"com.warmcat.sai.taskinfo\", \"js_api_version\": " + SAI_JS_API_VERSION +
						  ", \"offset\": " + current_overview_offset + "}");
					 // Populate the sidebar too
					 sai_sb_request_projects();
					 return;
			}

			if (eid) {
				 console.log("eid " + eid);
				 selected_event_uuid = eid;

				 sai.send("{\"schema\":" +
					  "\"com.warmcat.sai.eventinfo\"," +
					  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
					  "\"event_hash\":" +
					  JSON.stringify(eid) + "}");

				 // Also request the overview (unscoped, so the
				 // deep-linked event is included)
				 sai.send("{\"schema\":" +
					  "\"com.warmcat.sai.taskinfo\", \"js_api_version\": " + SAI_JS_API_VERSION +
					  ", \"offset\": " + current_overview_offset + "}");
				 // Populate the sidebar too
				 sai_sb_request_projects();
				 return;
			}

			/*
			 * No deep link: start the sidebar cascade by requesting
			 * the project list.  Its handler auto-selects the first
			 * project -> branchlist -> auto-select newest branch ->
			 * scoped overview.
			 *
			 * If the URL carries ?project= / ?branch= (a previously
			 * saved sidebar selection), pre-seed them so the cascade
			 * restores that view instead of the newest project/branch.
			 */
			{
				var _pp = par.get('project');
				var _bp = par.get('branch');
				if (_pp) sb_selected_project = _pp;
				if (_bp) sb_selected_ref = _bp;
			}

			 sai_sb_request_projects();
		};

		sai.onmessage = function got_packet(msg) {
			var u, ci, n;
			var now_ut = Math.round((new Date().getTime() / 1000));

		//	console.log(msg.data);
		//	if (msg.data.length < 10)
		//		return;
		try {
			jso = JSON.parse(msg.data);
		} catch (err) {
			console.log("Bad JSON received:", err.message);
			return;
		}
		//	console.log(jso.schema);

			if (jso.alang) {
				var a = jso.alang.split(","), n;

				for (n = 0; n < a.length; n++) {
					var b = a[n].split(";");
					switch (b[0]) {
					case "ja":
						i18n.translator.add(JSON.parse(lang_ja));
						n = a.length;
						break;
					case "zh_TW":
					case "zh_HK":
					case "zh_SG":
					case "zh_HANT":
					case "zh-TW":
					case "zh-HK":
					case "zh-SG":
					case "zh-HANT":
						i18n.translator.add(JSON.parse(lang_zht));
						n = a.length;
						break;
					case "zh":
					case "zh_CN":
					case "zh_HANS":
					case "zh-CN":
					case "zh-HANS":
						i18n.translator.add(JSON.parse(lang_zhs));
						n = a.length;
						break;
					case "en":
					case "en_US":
					case "en-US":
						n = a.length;
						break;
					}
				}
			}

			if (jso.api_version && jso.api_version !== SAI_JS_API_VERSION) {
				console.warn(`Sai JS API version mismatch. Client: ${SAI_JS_API_VERSION}, Server: ${jso.api_version}. Reloading page.`);
				location.reload(true); // Force a hard reload
				return; // Stop processing this old message
			}

			console.log(jso.schema);

			switch (jso.schema) {

			case "com.warmcat.sai.builders":
				/* Update builder list */
				let platformsArray = (jso.platforms && Array.isArray(jso.platforms)) ? jso.platforms :
				                     (jso.builders && Array.isArray(jso.builders)) ? jso.builders : null;

				if (platformsArray) {
					last_builder_list = platformsArray;
					
					/* Ensure PCONs exist in topology even if omitted by the server payload */
					last_builder_list.forEach(b => {
					    if (b.pcon && !pcon_topology[b.pcon]) {
					        pcon_topology[b.pcon] = {
					            name: b.pcon,
					            on: 0, /* Default to off so it shows grey until we get real state */
					            type: "",
					            depends_on: "",
					            children: []
					        };
					    }

					    if (!b.online) {
					        /* Builder became inactive, remove associated task steps */
					        for (const short_name in spreadsheet_data_cache) {
					            if (b.name.startsWith(short_name)) {
					                delete spreadsheet_data_cache[short_name];
					            }
					        }
					    }
					});

					const container = document.getElementById("sai_builders");
					if (container) renderPconHierarchy(container);
				}
				break;

			case "com.warmcat.sai.power_managed_builders":
				/* Update PCON topology */
				if (jso.power_controllers) {
					jso.power_controllers.forEach(pc => {
						pcon_topology[pc.name] = pc;
					});
					/* Trigger redraw if we have builders */
					const container = document.getElementById("sai_builders");
					if (container) renderPconHierarchy(container);
				}
				break;

			case "com.warmcat.sai.pcon_energy":
				if (jso.items) {
					jso.items.forEach(item => {
						pcon_energy_cache[item.name] = item;
						const pconDiv = document.getElementById("pcon-" + item.name);
						if (pconDiv) {
							let header = pconDiv.querySelector(".pcon-header");
							let stats = header.querySelector(".pcon-stats");
							if (!stats) {
								stats = document.createElement("span");
								stats.className = "pcon-stats";
								stats.style.marginLeft = "10px";
								stats.style.fontSize = "0.9em";
								stats.style.color = "#666";
								header.appendChild(stats);
							}

							const d = item;
							let hasPower = false;
							if (d.voltage_v < 70)
								stats.textContent = "unpowered";
							else if (!d.active_power_w)
								stats.textContent = "OFF";
							else {
								stats.textContent = `${d.active_power_w}W`;
								hasPower = true;
							}

							let plugIcon = header.querySelector("span");
							if (plugIcon) {
								plugIcon.className = hasPower ? "pcon-on" : "pcon-off";
							}
							
							const myBuilders = last_builder_list.filter(b => b.pcon === item.name);
							let anyConnected = myBuilders.some(b => b.online === 1);
							let anyPoweringUp = myBuilders.some(b => b.powering_up === 1);
							
							if (anyConnected || anyPoweringUp || hasPower) {
								header.classList.add("pcon-header-on");
							} else {
								header.classList.remove("pcon-header-on");
							}
						}
					});
					
					let total_w = 0;
					for (const p in pcon_energy_cache) {
						if (pcon_energy_cache[p].active_power_w)
							total_w += pcon_energy_cache[p].active_power_w;
					}
					updatePowerGraph(total_w);
				}
				break;

			case "com.warmcat.sai.power_history":
				sai_max_total_power_w = jso.max_w;
				sai_power_samples = [];
				if (jso.samples) {
					for (var j = 0; j < jso.samples.length; j++) {
						sai_power_samples.push(jso.samples[j]);
					}
				}
				updatePowerGraph(null); /* Redraw instantly without new sample */
				break;

			case "com.warmcat.sai.build-metric":
				var summaryDiv = document.getElementById("metrics-summary-" + jso.task_uuid);
				if (summaryDiv) {
					var s = "<div class=\"metric-summary\">" +
						"Step Metrics: " +
						"CPU: " + (jso.us_cpu_user / 1000000).toFixed(2) + "s user, " +
						(jso.us_cpu_sys / 1000000).toFixed(2) + "s sys; " +
						"Wallclock: " + (jso.wallclock_us / 1000000).toFixed(2) + "s; " +
						"Mem: " + humanize(jso.peak_mem_rss) + "B; " +
						"Stg: " + humanize(jso.stg_bytes) + "B; " +
						"Parallel: " + jso.parallel +
						"</div>";
					summaryDiv.innerHTML += s;
				}
				break;

			case "com.warmcat.sai.watcher_services":
				watcher_services = jso;
				break;

			case "com.warmcat.sai.ptydata":
				if (jso.task_uuid) {
					let term = active_terminals[jso.task_uuid];
					if (!term) {
						let platformStr = null;
						if (typeof last_builder_list !== 'undefined' && jso.builder_name) {
							const b = last_builder_list.find(x => x.name === jso.builder_name);
							if (b) platformStr = b.platform;
						}
						term = new SaiTerminal(document.body, {
							title: "Terminal: " + (jso.builder_name || "Unknown"),
							platform: platformStr,
							onData: function(input) {
								const msg = {
									schema: "com.warmcat.sai.ptydata",
									task_uuid: jso.task_uuid,
									channel: 0,
									len: input.length,
									data: btoa(input)
								};
								sai.send(JSON.stringify(msg));
							},
							onResize: function(cols, rows) {
								const msg = {
									schema: "com.warmcat.sai.ptydata",
									task_uuid: jso.task_uuid,
									channel: 0,
									cols: cols,
									rows: rows,
									len: 0,
									data: ""
								};
								sai.send(JSON.stringify(msg));
							},
							onClose: function() {
								const msg = {
									schema: "com.warmcat.sai.closeshell",
									task_uuid: jso.task_uuid
								};
								sai.send(JSON.stringify(msg));
								delete active_terminals[jso.task_uuid];
							}
						});

						active_terminals[jso.task_uuid] = term;
					}
					if (jso.data) {
						const binString = atob(jso.data);
						const bytes = new Uint8Array(binString.length);
						for (let i = 0; i < binString.length; i++) {
							bytes[i] = binString.charCodeAt(i);
						}
						const text = new TextDecoder().decode(bytes);
						term.write(jso.channel, text);
					}
				}
					break;

				case "com.warmcat.sai.projlist":
					/*
					 * Unique project names from the events db.
					 * On first receipt with no prior selection,
					 * auto-select the first project to drive the
					 * rest of the cascade.  Skip the auto-select
					 * for deep links (?event=/?task=) so the
					 * deep-linked event isn't displaced.
					 */
					sb_projects = (jso.projects && Array.isArray(jso.projects)) ? jso.projects : [];
					if (!sb_selected_project && !selected_event_uuid &&
					    !selected_task_uuid && sb_projects.length) {
						selectSbProject(sb_projects[0]);
					} else {
						render_sb_projects();
						/*
						 * If a project was pre-selected (e.g. from ?project=
						 * in the URL), drive the rest of the cascade for it:
						 * fetch its branch list.  When a branch is also
						 * pre-selected, the branchlist handler below will
						 * preserve it and fire the scoped overview.
						 */
						if (sb_selected_project && !sb_branches.length)
							sai_sb_request_branches(sb_selected_project);
					}
					break;

				case "com.warmcat.sai.branchlist":
					/*
					 * Unique refs for the selected project,
					 * newest-first.  Auto-select the most recent
					 * branch so col 4 populates immediately.
					 * branch_states (ref -> latest-event state) is
					 * optional; older servers omit it.
					 */
					sb_branches = (jso.branches && Array.isArray(jso.branches)) ? jso.branches : [];
					sb_branch_states = (jso.branch_states && typeof jso.branch_states === 'object')
								? jso.branch_states : {};
					if (!sb_selected_ref && sb_branches.length) {
						selectSbBranch(sb_branches[0]);
					} else {
						render_sb_branches();
						/*
						 * If a branch was pre-selected (e.g. from ?branch=),
						 * fire the scoped overview now that we know the
						 * branch list for this project.
						 */
						if (sb_selected_ref)
							sai_sb_request_overview(0);
					}
					break;

				case "sai.warmcat.com.overview":
				/*
				 * Sent with an array of e[] to start, but also
				 * can send a single e[] if it just changed
				 * state.  When scoped to the sidebar selection,
				 * the server only returns matching events.
				 */
				if (jso.overview) {
					jso.overview = jso.overview.filter(o => !deleted_events_cache.has(o.e.uuid));
					if (jso.overview.length === 0 && typeof jso.total_events === 'undefined') {
						break;
					}
				}

				/*
				 * Track the newest matching event before merge, so
				 * we can detect a brand-new event arriving in the
				 * current selection.
				 */
				var sb_newest_before = null;
				if (loaded_events && loaded_events.length) {
					var _tmp = loaded_events.filter(function(o) {
						if (!o || !o.e) return false;
						if (sb_selected_project && o.e.repo_name !== sb_selected_project) return false;
						if (sb_selected_ref && o.e.ref !== sb_selected_ref) return false;
						return true;
					});
					if (_tmp.length) {
						_tmp.sort(function(a, b) {
							return (b.e.created || 0) - (a.e.created || 0);
						});
						sb_newest_before = _tmp[0].e.uuid;
					}
				}

				if (jso.overview) {
					jso.overview.forEach(function(new_ev) {
						var idx = loaded_events.findIndex(o => o.e.uuid === new_ev.e.uuid);
						if (idx !== -1) {
							/*
							 * Preserve task data we may already hold for this
							 * event: a sidebar-scoped (summary) overview
							 * arrives with t:[] + summary/sum_counts, which
							 * would clobber the full task array fetched for
							 * the tasks pane (e.g. via a ?task= deep link).
							 * Keep the richer of the two: use the incoming
							 * tasks if it has them, else keep the existing.
							 */
							var merged = new_ev;
							if ((!new_ev.t || !new_ev.t.length) &&
							    loaded_events[idx].t && loaded_events[idx].t.length) {
								merged = Object.assign({}, new_ev);
								merged.t = loaded_events[idx].t;
							}
							loaded_events[idx] = merged;
						} else {
							loaded_events.push(new_ev);
						}
					});
					if (jso.overview.length > 1) {
						/*
						 * Carry over any full task arrays we already hold for
						 * events that the new (possibly summary-only) overview
						 * replaces with t:[], so the tasks pane keeps its data.
						 */
						var _old_by_uuid = {};
						loaded_events.forEach(function(o) {
							if (o && o.e && o.e.uuid && o.t && o.t.length)
								_old_by_uuid[o.e.uuid] = o.t;
						});
						jso.overview = jso.overview.map(function(new_ev) {
							if ((!new_ev.t || !new_ev.t.length) &&
							    new_ev.e && _old_by_uuid[new_ev.e.uuid]) {
								var m = Object.assign({}, new_ev);
								m.t = _old_by_uuid[new_ev.e.uuid];
								return m;
							}
							return new_ev;
						});
						loaded_events = jso.overview;
						if (typeof jso.total_events !== 'undefined') total_events = jso.total_events;
						if (typeof jso.offset !== 'undefined') current_offset = jso.offset;
					}
				}

				if (loaded_events.length > 0) {
					if (!selected_event_uuid) {
						if (selected_task_uuid) {
							var evUuid = find_event_by_task_uuid(selected_task_uuid);
							if (evUuid) selected_event_uuid = evUuid;
						}
						if (!selected_event_uuid) {
							/*
							 * With a sidebar selection, auto-pick the
							 * newest event matching it (eg after a branch
							 * switch cleared the selection); without one,
							 * take the newest event we hold.
							 */
							var _ne = sai_sb_newest_matching_event();
							if (_ne)
								selected_event_uuid = _ne.e.uuid;
							else if (!sb_selected_project && !sb_selected_ref)
								selected_event_uuid = loaded_events[loaded_events.length - 1].e.uuid;
						}
					}

					/*
					 * Deep-link (?event= / ?task=) support: if the
					 * URL pinned a specific event/task, derive the
					 * sidebar project + branch from it so the
					 * project and branch lists highlight the right
					 * entries.  We only do this once (until the
					 * user manually picks something else).
					 */
					var _deep = false;
					try {
						var _dp = new URLSearchParams(window.location.search);
						_deep = !!(_dp.get('event') || _dp.get('task'));
					} catch (e2) {}
					if (_deep && selected_event_uuid &&
					    !sb_selected_project && !sb_selected_ref) {
						var _dev = loaded_events.find(
							o => o.e.uuid === selected_event_uuid);
						if (_dev && _dev.e) {
							sb_selected_project = _dev.e.repo_name || null;
							sb_selected_ref = _dev.e.ref || null;
							render_sb_projects();
							render_sb_branches();
							/* refresh this project's branch list from
							 * the server so the highlight is correct */
							if (sb_selected_project)
								sai_sb_request_branches(sb_selected_project);
						}
					}
				}

				/*
				 * Fallback for older sai-web servers that don't
				 * (yet) answer projlist/branchlist: derive the
				 * unique projects and branches client-side from
				 * whatever events we have.  When a real projlist /
				 * branchlist reply arrives later it overrides this.
				 */
				if ((!sb_projects || !sb_projects.length) && loaded_events.length) {
					var _pset = {};
					loaded_events.forEach(function(o) {
						if (o && o.e && o.e.repo_name)
							_pset[o.e.repo_name] = 1;
					});
					sb_projects = Object.keys(_pset).sort();
					if (!sb_selected_project && sb_projects.length && !selected_event_uuid && !selected_task_uuid)
						sb_selected_project = sb_projects[0];
					render_sb_projects();
				}
				if (sb_selected_project && (!sb_branches || !sb_branches.length) && loaded_events.length) {
					var _bset = {};
					loaded_events.forEach(function(o) {
						if (o && o.e && o.e.repo_name === sb_selected_project && o.e.ref)
							_bset[o.e.ref] = o.e.created || 0;
					});
					/* sort refs newest-first by their latest event */
					sb_branches = Object.keys(_bset).sort(function(a, b) {
						return _bset[b] - _bset[a];
					});
					/*
					 * Derive the per-ref latest state client-side too,
					 * using the newest event per ref, so the fallback
					 * path colours branches identically to a real
					 * branchlist reply.
					 */
					sb_branch_states = {};
					sb_branches.forEach(function(ref) {
						var newest = null;
						loaded_events.forEach(function(o) {
							if (!o || !o.e || o.e.ref !== ref ||
							    o.e.repo_name !== sb_selected_project)
								return;
							if (!newest ||
							    (o.e.created || 0) > (newest.e.created || 0))
								newest = o;
						});
						if (newest)
							sb_branch_states[ref] = newest.e.state;
					});
					if (!sb_selected_ref && sb_branches.length)
						sb_selected_ref = sb_branches[0];
					render_sb_branches();
				}

				render_event_decals();

				/*
				 * If a brand-new event for the current selection
				 * arrived, auto-select it (matches the "live"
				 * requirement: new matching event appears at the
				 * top of col 4 and is selected).
				 */
				var sb_newest_after = null;
				if (loaded_events && loaded_events.length) {
					var _tmp2 = loaded_events.filter(function(o) {
						if (!o || !o.e) return false;
						if (sb_selected_project && o.e.repo_name !== sb_selected_project) return false;
						if (sb_selected_ref && o.e.ref !== sb_selected_ref) return false;
						return true;
					});
					if (_tmp2.length) {
						_tmp2.sort(function(a, b) {
							return (b.e.created || 0) - (a.e.created || 0);
						});
						sb_newest_after = _tmp2[0].e.uuid;
					}
				}
				if (sb_newest_after && sb_newest_after !== sb_newest_before &&
				    (sb_selected_project || sb_selected_ref)) {
					/*
					 * Only auto-jump to a brand-new event when
					 * we're in the sidebar-driven flow (a
					 * selection exists); deep links keep their
					 * explicitly-selected event.
					 */
					selectEvent(sb_newest_after);
				} else {
					if (selected_event_uuid) {
						var ev_obj = loaded_events.find(o => o.e.uuid === selected_event_uuid);
						if (ev_obj) {
							render_selected_event_tasks(ev_obj);
						}
					}
				}

				/*
				 * Keep the selected branch's colour live: the
				 * overview is scoped to the selection, so only the
				 * selected ref can have a newer event here; other
				 * branches refresh on the next branchlist fetch.
				 */
				sai_sb_branch_state_livecheck();

				aging();
				break;

			case "com.warmcat.sai.taskinfo":

				if (!jso.t)
					break;

				if (new URLSearchParams(window.location.search).get('task') === jso.t.uuid) {
					window.current_viewed_task_state = jso.t.state;
				}

				if (loaded_events) {
					var event_uuid = jso.t.uuid.substring(0, 32);
					var ev_obj = loaded_events.find(function(o) { return o.e.uuid === event_uuid; });
					if (ev_obj) {
						if (jso.e) {
							ev_obj.e = Object.assign({}, ev_obj.e, jso.e);
						}
						if (ev_obj.t) {
							var t_run = typeof jso.t.run !== 'undefined' ? jso.t.run : 0;
							var t_idx = ev_obj.t.findIndex(function(t) { return t.uuid === jso.t.uuid && (typeof t.run !== 'undefined' ? t.run : 0) === t_run; });
							if (t_idx !== -1) {
								ev_obj.t[t_idx] = Object.assign({}, ev_obj.t[t_idx], jso.t);
							} else {
								ev_obj.t.push(jso.t);
							}
						}
					}
					/*
					 * A task state change can flip the event's
					 * state; reflect it in the selected branch's
					 * colour without a full branchlist round-trip.
					 */
					sai_sb_branch_state_livecheck();
				}

				if (document.getElementById("taskstate_" + jso.t.uuid)) {
					console.log("found taskstate_" + jso.t.uuid);
					refresh_state(jso.t);
					update_summary_and_progress(jso.t.uuid.substring(0, 32));
				}

				/* update task summary if shown anywhere */
				if (document.getElementById("taskinfo-" + jso.t.uuid)) {
					if (typeof window.current_task_run !== 'undefined' && window.current_task_run !== jso.t.run) {
						if (document.getElementById("sai-task-logs"))
							document.getElementById("sai-task-logs").innerHTML = "";
						/* update the URL without reloading so sharing works */
						var par = new URLSearchParams(window.location.search);
						par.set('run', jso.t.run);
						sai_update_history(par, true);
					}
					window.current_task_run = jso.t.run;
					var ti_el = document.getElementById("taskinfo-" + jso.t.uuid);
					ti_el.className = "taskinfo taskstate" + jso.t.state;
					ti_el.innerHTML = sai_taskinfo_render(jso);
					if (jso.e) {
						if (document.getElementById("esr-" + jso.e.uuid))
							document.getElementById("esr-" + jso.e.uuid).innerHTML =
								sai_event_summary_render(jso, now_ut, 1);
						update_summary_and_progress(jso.e.uuid);
					}
				}

				if (!document.getElementById("taskstate_" + jso.t.uuid) &&
				    !document.getElementById("taskinfo-" + jso.t.uuid)) {

					console.log("NO taskinfo- or taskstate_" + jso.t.uuid);

					/*
					 * Last chance if we might be
					 * on a task-specific page, and
					 * want to show the task info
					 * at the top
					 */

					const urlParams = new URLSearchParams(window.location.search);
					const url_task_uuid = urlParams.get('task');

					if (url_task_uuid === jso.t.uuid &&
					    document.getElementById("sai_sticky")) {
						window.current_task_run = jso.t.run;
						document.getElementById("sai_sticky").innerHTML =
							"<div class=\"taskinfo taskstate" + jso.t.state + "\" id=\"taskinfo-" +
							san(jso.t.uuid) + "\">" +
							sai_taskinfo_render(jso) +
							"</div>";

						s = "<table><td colspan=\"3\"><pre><table class=\"scrollogs\"><tr>" +
						"<td class=\"atop\">" +
						"<div id=\"dlogsn\" class=\"dlogsn\">" + lines + "</div></td>" +
						"<td class=\"atop\">" +
						"<div id=\"dlogst\" class=\"dlogst\">" + times + "</div></td>" +
						 "<td class=\"atop\"><div id=\"dlogs\" class=\"dlogs\">" +
						 "<span id=\"logs\" class=\"nowrap\">" + logs +
						"</span>"+
						"</div></td></tr></table></pre>";

						if (document.getElementById("sai_overview")) {
							document.getElementById("sai_overview").innerHTML = s;
							logs_pending = times_pending = lines_pending = "";

							if (jso.e && document.getElementById("esr-" + jso.e.uuid))
								document.getElementById("esr-" + jso.e.uuid).innerHTML =
									sai_event_summary_render(jso, now_ut, 1);

						}
					}
				}
				if (jso.e)
					update_summary_and_progress(jso.e.uuid);

				if (document.getElementById("rebuild-" + san(jso.t.uuid))) {
					document.getElementById("rebuild-" + san(jso.t.uuid)).
						addEventListener("click", function(e) {
							var rs= "{\"schema\":" +
							 "\"com.warmcat.sai.taskreset\"," +
							 "\"uuid\": " +
								JSON.stringify(san(e.srcElement.id.substring(8))) + "}";

							console.log(rs);
							sai.send(rs);

							var tid = san(e.srcElement.id.substring(8));
							if (new URLSearchParams(window.location.search).get('run')) {
								window.location.search = '?task=' + tid;
								return;
							}

							/*
							 * and immediately re-request the task info, so we can get
							 * the new logs
							 */
							var rq = "{\"schema\":" +
								  "\"com.warmcat.sai.taskinfo\"," +
								  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
								  "\"logs\": 1," +
								  "\"run\": -1," +
								  "\"last_log_ts\":" + last_log_timestamp + ",\"last_log_uid\":" + last_log_uid + "," +
								  "\"task_hash\":" +
								  JSON.stringify(tid) + "}";

							console.log(rq);
							sai.send(rq);

							document.getElementById("dlogsn").innerHTML = "";
							document.getElementById("dlogst").innerHTML = "";
							document.getElementById("dlogs").innerHTML = "<span id=\"logs\" class=\"nowrap\"></span>";
							lines = times = logs = "";
							lines_pending = times_pending = logs_pending = "";
							segment_stack = [];
							seg_counter = 0;
							window.held_start_line = null;
							logAnsiState = {};
							tfirst = 0;
							lli = 1;
							last_log_timestamp = 0;
						});
				}

				if (document.getElementById("stop-" + san(jso.t.uuid))) {
					document.getElementById("stop-" + san(jso.t.uuid)).
						addEventListener("click", function(e) {
							var rs= "{\"schema\":" +
							 "\"com.warmcat.sai.taskcan\"," +
							 "\"task_uuid\": " +
								JSON.stringify(san(e.srcElement.id.substring(5))) + "}";
							 console.log(rs);
							sai.send(rs);
						});
				}

				aging();
				break;

			case "com.warmcat.sai.loadreport":
				// Cache the whole report for subsequent builder redraws
				loadreport_data_cache[jso.builder_name] = jso;

				const builderDiv = document.getElementById('binfo-' + jso.builder_name);
				if (builderDiv) {
					const cpuBar = builderDiv.querySelector(".res-bar-cpu");
					const ramBar = builderDiv.querySelector(".res-bar-ram");
					const diskBar = builderDiv.querySelector(".res-bar-disk");

					if (cpuBar) {
						let cpu_percentage = jso.cpu_percent / 10;
						if (cpu_percentage > 100) cpu_percentage = 100;
						if (cpu_percentage < 0) cpu_percentage = 0;
						let width_class = `w-${Math.round(cpu_percentage / 5) * 5}`;

						cpuBar.classList.forEach(c => { if (c.startsWith('w-')) cpuBar.classList.remove(c); });
						cpuBar.classList.add(width_class);
					}
					if (ramBar) {
						let ram_percentage = 0;
						if (jso.initial_free_ram_kib > 0) {
							ram_percentage = (jso.reserved_ram_kib / jso.initial_free_ram_kib) * 100;
						}
						if (ram_percentage > 100) ram_percentage = 100;
						if (ram_percentage < 0) ram_percentage = 0;

						let width = Math.round(ram_percentage / 5) * 5;
						if (width === 0 && ram_percentage > 0)
							width = 5;

						let width_class = `w-${width}`;

						ramBar.classList.forEach(c => { if (c.startsWith('w-')) ramBar.classList.remove(c); });
						ramBar.classList.add(width_class);
					}
					if (diskBar) {
						let disk_percentage = 0;
						if (jso.initial_free_disk_kib > 0) {
							disk_percentage = (jso.reserved_disk_kib / jso.initial_free_disk_kib) * 100;
						}
						if (disk_percentage > 100) disk_percentage = 100;
						if (disk_percentage < 0) disk_percentage = 0;

						let width = Math.round(disk_percentage / 5) * 5;
						if (width === 0 && disk_percentage > 0)
							width = 5;

						let width_class = `w-${width}`;

						diskBar.classList.forEach(c => { if (c.startsWith('w-')) diskBar.classList.remove(c); });
						diskBar.classList.add(width_class);
					}
				}

				// Part 2: Update the spreadsheet of active tasks for the builder
				if (jso.active_tasks && jso.active_tasks.length > 0)
					spreadsheet_data_cache[jso.builder_name] = jso.active_tasks;
				else
					delete spreadsheet_data_cache[jso.builder_name];

				const spreadsheetContainer = document.getElementById('spreadsheet-' + jso.builder_name);
				if (spreadsheetContainer) {
					updateSpreadsheetDOM(spreadsheetContainer, spreadsheet_data_cache[jso.builder_name]);
					if (spreadsheet_data_cache[jso.builder_name]) {
						aging();
					}
				}
				break;

			case "com-warmcat-sai-artifact":
				console.log(jso);

				sai_arts += "<div class=\"sai_arts\"><img src=\"artifact.svg\">&nbsp;<a href=\"/sai/artifacts/" +
					san(jso.task_uuid) + "/" +
					san(jso.artifact_down_nonce) + "/" +
					san(jso.blob_filename) + "\">" +
					san(jso.blob_filename) + "</a>&nbsp;" +
					humanize(jso.len) + "B </div>";

				if (document.getElementById("sai_arts"))
					document.getElementById("sai_arts").innerHTML = sai_arts;

				break;

			case "com.warmcat.sai.taskactivity":
				ongoing_task_activities = {};
				if (jso.activity) {
					for (var i = 0; i < jso.activity.length; i++) {
						var act = jso.activity[i];
						ongoing_task_activities[act.uuid] = act.cat;
					}
				} else
						console.log("no spreadsheetContainer");
				break;

			case "com.warmcat.sai.cloneinfo":
				sai_adhoc_dialog_open(jso);
				break;

			case "com.warmcat.sai.unauthorized":
				location.reload();
				break;

			case "com.warmcat.sai.findings":
				sai_findings = jso;
				sai_findings_update_button();
				sai_findings_render();
				break;

			case "com.warmcat.sai.finding":
				sai_findings_show_detail(jso);
				break;

		case "com.warmcat.sai.auth_state":
			console.log("Backend auth_state:", jso.auth_state);
			if (jso.auth_state === 3) {
				auth_state = SaiAuthState.LOGGED_IN_GRANT_ADMIN;
				auth_is_admin = 1;
			} else if (jso.auth_state === 2) {
				auth_state = SaiAuthState.LOGGED_IN_GRANT_USER;
				auth_is_admin = 0;
			} else if (jso.auth_state === 1) {
				auth_state = SaiAuthState.LOGGED_IN_NO_GRANT;
				auth_is_admin = 0;
			} else {
				auth_state = SaiAuthState.NOT_LOGGED_IN;
				auth_is_admin = 0;
			}
				sai_findings_auth_changed();
				const statusContainer = document.getElementById('lws-login-status-container');
				if (statusContainer) {
					statusContainer.classList.remove('grant-admin', 'grant-user', 'grant-none');
					if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
						statusContainer.classList.add('grant-admin');
					} else if (auth_state === SaiAuthState.LOGGED_IN_GRANT_USER) {
						statusContainer.classList.add('grant-user');
					} else if (auth_state === SaiAuthState.LOGGED_IN_NO_GRANT) {
						statusContainer.classList.add('grant-none');
					}
				}
				/*
				 * The admin restart-all / delete-event buttons now
				 * live in the tasks-section header, which is gated
				 * on auth_state; re-render it so they appear /
				 * disappear on login state changes.
				 */
				if (selected_event_uuid) {
					var _ev = loaded_events.find(o => o.e.uuid === selected_event_uuid);
					if (_ev)
						render_selected_event_tasks(_ev);
				}
				break;

			case "com.warmcat.sai.event_deleted":
				window.location.href = window.location.origin + window.location.pathname;
				break;

			/*
			 * sai-web is about to send this task's logs from the
			 * first row again: what we are showing is either gone
			 * (the task's tries were removed) or belongs to an
			 * earlier run, so drop it rather than appending under it
			 */
			case "com.warmcat.sai.logs_reset":
				if (jso.task_hash === selected_task_uuid)
					sai_reset_log_pane(0);
				break;

			case "com-warmcat-sai-logs":
				var s1;
				try {
					var binString = atob(jso.log);
					if (window.TextDecoder) {
						window._sai_text_decoder = window._sai_text_decoder || new TextDecoder("utf-8");
						var bytes = new Uint8Array(binString.length);
						for (var i = 0; i < binString.length; i++) {
							bytes[i] = binString.charCodeAt(i);
						}
						s1 = window._sai_text_decoder.decode(bytes, {stream: true});
					} else {
						s1 = decodeURIComponent(escape(binString));
					}
				} catch (e) {
					console.log("decode err", e);
					break;
				}

				if (window._sai_ansi_buffer) {
					s1 = window._sai_ansi_buffer + s1;
					window._sai_ansi_buffer = "";
				}

				var last_esc = s1.lastIndexOf('\u001b');
				if (last_esc >= 0) {
					var tail = s1.substring(last_esc);
					var is_complete = true;
					if (tail.startsWith('\u001b[')) {
						is_complete = /(\u001b\[[0-9:;<=>?]*[ -/]*[@-~])/.test(tail);
					} else if (tail.startsWith('\u001b]')) {
						is_complete = tail.indexOf('\x07') !== -1 || tail.indexOf('\u001b\\', 1) !== -1;
					} else if (tail === '\u001b') {
						is_complete = false;
					}
					
					if (!is_complete && tail.length < 512) {
						window._sai_ansi_buffer = tail;
						s1 = s1.substring(0, last_esc);
					}
				}

				if (!tfirst) tfirst = jso.timestamp;
				last_log_timestamp = jso.timestamp;
				if (jso.uid > last_log_uid)
					last_log_uid = jso.uid;

				/* normalize CRs to LFs so line number counts track them properly */
				if (window._sai_cr_pending && s1.startsWith('\n')) {
					s1 = s1.substring(1);
				}
				window._sai_cr_pending = s1.endsWith('\r');
				s1 = s1.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

				var lines_started = 0;
				var lines_arr = s1.split('\n');
				for (var idx = 0; idx < lines_arr.length; ++idx) {
					if (idx === lines_arr.length - 1 && lines_arr[idx] === '') continue;
					
					var text_line = lines_arr[idx];
					var has_nl = (idx < lines_arr.length - 1) ? '\n' : '';
					var line_str = text_line + has_nl;
					
					var ansiResult = ansiToHtml(line_str, logAnsiState);
					var s = ansiResult.html;
					logAnsiState = ansiResult.newState;
					
					var li = has_nl ? 1 : 0;
					var en = "", tn = "";
					if (cont && !cont[jso.channel] && jso.len)
						tn = ((jso.timestamp - tfirst) / 1000000).toFixed(4);

					var temp_li = li;
					var temp_lli = lli;
					while (temp_li > 0) {
						en += "<a id=\"#sn" + temp_lli + "\" href=\"#sn" + temp_lli + "\">" + temp_lli + "</a><br>";
						tn += "<br>";
						temp_lli++;
						temp_li--;
					}
					
					var s_logs = "";
					switch (jso.channel) {
					case 1: s_logs = s; break;
					case 2: s_logs = "<span class=\"stderr\">" + s + "</span>"; break;
					case 3: s_logs = "<span class=\"saibuild\">\u{25a0} " + s + "</span>"; break;
					case 4: s_logs = "<span class=\"tty0\">" + s + "</span>"; break;
					default: s_logs = "<span class=\"tty1\">" + s + "</span>"; break;
					}

					var eval_line = text_line;
					if (window.pending_log_line && idx === 0) {
						eval_line = window.pending_log_line + text_line;
					}
					
					if (has_nl === '') {
						window.pending_log_line = eval_line;
					} else if (idx === 0) {
						window.pending_log_line = "";
					}

					var skip_push = false;
					var skip_render = false;
					var match_fail = (jso.channel === 1 || jso.channel === 2) ? eval_line.match(/Test\s+#(\d+):\s+.*(Failed|\*\*\*|Timeout)/i) : null;
					var is_fail = match_fail || ((jso.channel === 1 || jso.channel === 2) && /test failed/i.test(eval_line));
					
					if (jso.channel === 1 || jso.channel === 2) {
						if (window.held_start_line) {
							if (is_fail) {
								var is_same_test = false;
								if (match_fail) {
									var start_match = window.held_start_line.text.match(/Start\s+(\d+):/i);
									if (start_match && start_match[1] === match_fail[1]) {
										is_same_test = true;
									}
								}
								// If the failing test isn't the one that just started, it must be running in parallel.
								// Flush the unrelated valid 'Start' line out into the parent CTest boundary first.
								if (!is_same_test) {
									logs += window.held_start_line.s_logs; logs_pending += window.held_start_line.s_logs;
									if (window.held_start_line.li) {
										lines += window.held_start_line.en; lines_pending += window.held_start_line.en;
										times += window.held_start_line.tn; times_pending += window.held_start_line.tn;
									}
									window.held_start_line = null;
								}
							
								while (segment_stack.length > 1) pop_segment();
								push_segment(eval_line, true);
								skip_push = true;
							}
							
							if (window.held_start_line) {
								logs += window.held_start_line.s_logs; logs_pending += window.held_start_line.s_logs;
								if (window.held_start_line.li) {
									lines += window.held_start_line.en; lines_pending += window.held_start_line.en;
									times += window.held_start_line.tn; times_pending += window.held_start_line.tn;
								}
								window.held_start_line = null;
							}
						}
						
						if (/^\s*Start\s+\d+:/i.test(eval_line)) {
							window.held_start_line = { text: eval_line, s_logs: s_logs, en: en, tn: tn, li: li };
							skip_render = true;
						}
					}

					if (jso.channel === 3) {
						if (/^>saib>\s+Starting task step/.test(eval_line)) {
							while (segment_stack.length > 0) pop_segment();
							push_segment(eval_line, true);
						} else if (/^>saib>\s+Step \d+:/.test(eval_line) && segment_stack.length > 0) {
							var pseg = segment_stack[0];
							var phdr = document.getElementById("hdr-seg-" + pseg.id);
							if (phdr) phdr.querySelector('.seg-title').innerText = eval_line;
						} else {
							while (segment_stack.length > 1) pop_segment();
						}
					}
					
					if (jso.channel === 1 || jso.channel === 2) {
						if (skip_push) {
							// Fold logic successfully handled during lookahead execution
						} else if (match_fail || /test failed/i.test(eval_line)) {
							while (segment_stack.length > 1) pop_segment();
							push_segment(eval_line, true);
						} else if (/^\d+% tests passed/i.test(eval_line) || /Total Test time/i.test(eval_line) || /The following tests FAILED:/i.test(eval_line) || /Errors while running CTest/i.test(eval_line)) {
							while (segment_stack.length > 1) pop_segment();
						} else if (/^\d+\/\d+\s+Test\s+#\d+:/i.test(eval_line)) {
							while (segment_stack.length > 1) pop_segment();
						}
					}
					
					var text_lower = eval_line.toLowerCase();
					if (is_fail || text_lower.includes("error:") || text_lower.includes("fatal:") || /error\s+[a-z0-9_]+:/i.test(text_lower)) {
						for (var si = 0; si < segment_stack.length; si++) {
							var sobj = segment_stack[si];
							sobj.error_count++;
							if (si < segment_stack.length - 1) {
								var sbody = document.getElementById("seg-" + sobj.id);
								var shdr = document.getElementById("hdr-seg-" + sobj.id);
								if (sbody && shdr && sbody.classList.contains("hide")) {
									sbody.classList.remove("hide");
									var sicon = shdr.querySelector('.fold-icon');
									if (sicon) sicon.innerText = "▼";
								}
							}
						}
					} else if (text_lower.includes("warning:")) {
						for (var si = 0; si < segment_stack.length; si++) segment_stack[si].warning_count++;
					}

					if (segment_stack.length > 0) {
						segment_stack[segment_stack.length - 1].lines_count += (has_nl ? 1 : 0);
					}

					if (!skip_render) {
						if (s_logs) {
							logs += s_logs; logs_pending += s_logs;
						}
						if (li) {
							lines += en; lines_pending += en;
							times += tn; times_pending += tn;
						}
					}

					if (cont)
						cont[jso.channel] = (li === 0);

					while (li > 0) {
						lli++;
						li--;
					}

				}

				if (!redpend) {
					redpend = 1;
					setTimeout(function() {
						const rightPane = document.getElementById('sai_overview') || document.querySelector('.right-pane');
						redpend = 0;
						if (rightPane)
							locked = rightPane.scrollHeight -
								rightPane.clientHeight <=
								rightPane.scrollTop + 1;

						if (locked) {
							for (var si = 0; si < segment_stack.length; si++) {
								var sobj = segment_stack[si];
								var sdom = document.getElementById("seg-" + sobj.id);
								var hdom = document.getElementById("hdr-seg-" + sobj.id);
								if (sdom && sdom.classList.contains("hide")) {
									sdom.classList.remove("hide");
									sobj.auto_unfolded = true;
									if (hdom) {
										var icon = hdom.querySelector('.fold-icon');
										if (icon) icon.innerText = "▼";
									}
								}
							}
						}

						flush_segments();
						check_and_apply_failure_ui();

						if (locked && rightPane)
						   rightPane.scrollTop =
							rightPane.scrollHeight -
							rightPane.clientHeight;
					}, 500);
				}

		break;
	} /* switch */
	} /* onmessage */
		sai.onerror = function(ev) {
			console.log("WebSocket error:", ev);
		};

		sai.onclose = function(ev){
			console.log("WebSocket closed. Code:", ev.code, "Reason:", ev.reason);
			
			if (typeof overlayTimeout !== 'undefined' && overlayTimeout) clearTimeout(overlayTimeout);
			
			window.overlayTimeout = setTimeout(function() {
				if (!document.querySelector(".overlay")) {
					var overlay = document.createElement("div");
					overlay.className = "overlay";
					document.body.appendChild(overlay);
					document.body.classList.add("overlay-active");
				}
			}, 3000);

			myVar = setTimeout(ws_open_sai, 1000);
		};
	} catch(exception) {
		alert("<p>Error" + exception);
	}
}

/* stuff that has to be delayed until all the page assets are loaded */

window.addEventListener("load", function() {
	var fbtn = document.getElementById("sai_findings_btn");

	if (fbtn)
		fbtn.addEventListener("click", sai_findings_dialog_open);


	document.addEventListener('click', function(e) {
		var hdr = e.target.closest('.log-segment-header');
		if (hdr) {
			var id = hdr.id.substring(8);
			toggleSegment(id);
		}
		/* task table: column header picks the sort, row picks the task */
		var tth = e.target.closest('th.tt-th');
		if (tth) {
			sai_tt_sort_click(tth.dataset.key);
			return;
		}
		var ttr = e.target.closest('tr.tt-row');
		if (ttr) {
			selectTask(ttr.dataset.taskUuid, '-1');
			return;
		}
		var pbtn = e.target.closest('.sai-pagination-btn');
		if (pbtn) {
			if (window.change_page) {
				window.change_page(parseInt(pbtn.getAttribute('data-offset')));
			}
		}

		var a = e.target.closest('a');
		if (a) {
			var href = a.getAttribute('href');
			if (href && (href.indexOf('?task=') !== -1 || href.indexOf('index.html?task=') !== -1)) {
				e.preventDefault();
				var urlParams = new URLSearchParams(href.substring(href.indexOf('?')));
				var taskUuid = urlParams.get('task');
				var runVal = urlParams.get('run') || '-1';
				selectTask(taskUuid, runVal);
			}
		}

		var rebuildBtn = e.target.closest("[id^='rebuild-']");
		if (rebuildBtn && !rebuildBtn.id.startsWith("rebuild-ev-")) {
			var tid = rebuildBtn.id.substring(8);
			var rs = "{\"schema\":\"com.warmcat.sai.taskreset\",\"uuid\":" + JSON.stringify(san(tid)) + "}";
			console.log(rs);
			sai.send(rs);

			// Clear logs and re-request taskinfo
			sai_reset_log_pane(0);

			var rq = "{\"schema\":\"com.warmcat.sai.taskinfo\",\"js_api_version\":" + SAI_JS_API_VERSION + ",\"logs\":1,\"run\":-1,\"last_log_ts\":" + last_log_timestamp + ",\"last_log_uid\":" + last_log_uid + ",\"task_hash\":" + JSON.stringify(tid) + "}";
			console.log(rq);
			sai.send(rq);
		}

		var stopBtn = e.target.closest("[id^='stop-']");
		if (stopBtn) {
			var tid = stopBtn.id.substring(5);
			var rs = "{\"schema\":\"com.warmcat.sai.taskcan\",\"task_uuid\":" + JSON.stringify(san(tid)) + "}";
			console.log(rs);
			sai.send(rs);
		}

		var rebuildEvBtn = e.target.closest("[id^='rebuild-ev-']");
		if (rebuildEvBtn) {
			var uuid = rebuildEvBtn.id.substring(11);
			var rs = "{\"schema\":\"com.warmcat.sai.eventreset\",\"uuid\":" + JSON.stringify(san(uuid)) + "}";
			console.log(rs);
			sai.send(rs);
		}

		var deleteEvBtn = e.target.closest("[id^='delete-ev-']");
		if (deleteEvBtn) {
			var uuid = deleteEvBtn.id.substring(10);
			deleted_events_cache.add(uuid);
			var rs = "{\"schema\":\"com.warmcat.sai.eventdelete\",\"uuid\":" + JSON.stringify(uuid) + "}";
			console.log(rs);
			sai.send(rs);

			// Remove / hide the event row in the sidebar
			var card = document.querySelector(".sb-event-row[data-uuid='" + uuid + "']");
			if (card) {
				card.style.transition = 'opacity 0.3s';
				card.style.opacity = '0';
				setTimeout(function() {
					if (card.parentNode) {
						card.parentNode.removeChild(card);
					}
				}, 300);
			}

			// Clean up selected state if the deleted event was currently selected
			if (selected_event_uuid === uuid) {
				var active_events = loaded_events.filter(o => !deleted_events_cache.has(o.e.uuid));
				if (active_events.length > 0) {
					var next_selected_uuid = active_events[active_events.length - 1].e.uuid;
					selectEvent(next_selected_uuid);
				} else {
					selected_event_uuid = null;
					selected_task_uuid = null;
					window.current_task_run = null;

					var tasksSection = document.getElementById("sai_event_tasks");
					if (tasksSection) {
						tasksSection.innerHTML = "<div class=\"event-tasks-header\"><span class=\"event-tasks-title\">No event selected</span></div>";
					}

					var stickyEl = document.getElementById("sai_sticky");
					var overviewEl = document.getElementById("sai_overview");
					if (stickyEl) stickyEl.innerHTML = "";
					if (overviewEl) overviewEl.innerHTML = "";

					var par = new URLSearchParams(window.location.search);
					par.delete("task");
					par.delete("run");
					par.delete("event");
					sai_update_history(par, false);
				}
			}
		}
	});

	const savedFlex = localStorage.getItem('sai-right-pane-flex');
	if (savedFlex) {
		const rightPane = document.querySelector('.right-pane');
		if (rightPane) {
			rightPane.style.flex = savedFlex;
		}
	}

	const lnameInput = document.getElementById("lname");
	const lpassInput = document.getElementById("lpass");

	function stopClickPropagation(event) {
		// This is the key. It prevents the click event from
		// reaching any parent elements.
		event.stopPropagation();
	}

	if (lnameInput) {
		lnameInput.addEventListener("click", stopClickPropagation);
	}

	if (lpassInput) {
		lpassInput.addEventListener("click", stopClickPropagation);
	}

	if (document.getElementById("noscript"))
		document.getElementById("noscript").display = "none";

	/* LWS Login hook */
	var loginPromise = Promise.resolve();
	if (window.renderLwsLoginStatus)
		loginPromise = window.renderLwsLoginStatus('lws-login-status-container');

	loginPromise.then(function() {
		return fetch('.lws-login-status');
	})
	.then(function(res) { return res.json(); })
	.then(function(data) {
		console.log("LOGIN STATUS DEBUG:", data);
		auth_state = SaiAuthState.NOT_LOGGED_IN;
		if (data.logged_in) {
			if (data.has_grant) {
				authd = 1;
				auth_grant_level = data.grant_level !== undefined ? data.grant_level : -1;
				const isAdmin = data.is_admin === true || data.is_admin === 1 || data.is_admin === "true" || data.is_admin === "1";
				if (auth_grant_level >= 2 || isAdmin) {
					auth_state = SaiAuthState.LOGGED_IN_GRANT_ADMIN;
					auth_is_admin = 1;
				} else {
					auth_state = SaiAuthState.LOGGED_IN_GRANT_USER;
				}
			} else {
				auth_state = SaiAuthState.LOGGED_IN_NO_GRANT;
			}

			sai_findings_auth_changed();

			const container = document.getElementById('lws-login-status-container');
			if (container) {
				container.classList.remove('grant-admin', 'grant-user', 'grant-none');
				if (auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
					container.classList.add('grant-admin');
				} else if (auth_state === SaiAuthState.LOGGED_IN_GRANT_USER) {
					container.classList.add('grant-user');
				} else if (auth_state === SaiAuthState.LOGGED_IN_NO_GRANT) {
					container.classList.add('grant-none');
				}
			}

			/*
			 * Re-render the tasks pane header so the admin
			 * restart-all / delete-event buttons appear now that
			 * auth_state has resolved (the buttons are gated on
			 * LOGGED_IN_GRANT_ADMIN and are absent from the initial
			 * render while auth_state was still NOT_LOGGED_IN).
			 */
			if (selected_event_uuid) {
				var _ev = loaded_events.find(o => o.e.uuid === selected_event_uuid);
				if (_ev)
					render_selected_event_tasks(_ev);
			}
		}
	})
	.catch(function(err) {
		console.log('lws-login auth fetch failed: ', err);
	})
	.finally(function() {
		ws_open_sai();
		aging();
	});

	setInterval(function() {
		update_task_activities();
		sai_tt_tick();

	    var locked = document.body.scrollHeight -
		document.body.clientHeight <= document.body.scrollTop + 1;

	    if (locked)
	     document.body.scrollTop = document.body.scrollHeight -
		document.body.clientHeight;

	}, 500)

	document.addEventListener("contextmenu", function(event) {
		let target = event.target;
		let taskDiv = null;

		// find the taskstate div parent
		while (target && target !== document.body) {
			if (target.classList && (target.classList.contains("taskstate") ||
						 target.classList.contains("tt-row"))) {
				taskDiv = target;
				break;
			}
			target = target.parentElement;
		}

		if (taskDiv && auth_state === SaiAuthState.LOGGED_IN_GRANT_ADMIN) {
			event.preventDefault();

			const taskUuid = taskDiv.dataset.taskUuid || taskDiv.id.substring(10);
			const eventUuid = taskDiv.dataset.eventUuid;
			const platform = taskDiv.dataset.platform;

			const menuItems = [
				{
					label: "Rebuild this task",
					callback: () => {
						sai.send(JSON.stringify({
							schema: "com.warmcat.sai.taskreset",
							uuid: taskUuid
						}));
					}
				},
				{
					/*
					 * Seed a new single-task event from this
					 * one; sai-web answers with cloneinfo and
					 * we open the dialog from that
					 */
					label: "Ad-hoc build from this task…",
					callback: () => {
						sai.send(JSON.stringify({
							schema: "com.warmcat.sai.cloneinfo",
							uuid: taskUuid
						}));
					}
				},
				{
					label: "Remove all tries",
					callback: () => {
						sai.send(JSON.stringify({
							schema: "com.warmcat.sai.taskremovealltries",
							uuid: taskUuid
						}));
					}
				},
				{
					label: `Rebuild all <b>${hsanitize(platform)}</b>`,
					callback: () => {
						sai.send(JSON.stringify({
							schema: "com.warmcat.sai.platreset",
							event_uuid: eventUuid,
							platform: platform
						}));
					}
				}
			];

			const isFinalState = ["taskstate3", "taskstate4", "taskstate5", "taskstate7", "taskstate11"].some(s => taskDiv.classList.contains(s));

			if (!isFinalState) {
				if (taskDiv.classList.contains("taskstate10")) {
					menuItems.push({
						label: "Continue task",
						callback: () => {
							sai.send(JSON.stringify({
								schema: "com.warmcat.sai.taskresume",
								uuid: taskUuid
							}));
						}
					});
				} else {
					menuItems.push({
						label: "Pause task",
						callback: () => {
							sai.send(JSON.stringify({
								schema: "com.warmcat.sai.taskpause",
								uuid: taskUuid
							}));
						}
					});
					menuItems.push({
						label: "Kill task",
						callback: () => {
							sai.send(JSON.stringify({
								schema: "com.warmcat.sai.taskkill",
								uuid: taskUuid
							}));
						}
					});
				}
			}

			if (taskDiv.dataset.rebuildable === "1")
				menuItems.splice(1, 0, {
					label: "Rebuild last step",
					callback: () => {
						sai.send(JSON.stringify({
							schema: "com.warmcat.sai.taskrebuildlaststep",
							uuid: taskUuid
						}));
					}
				});

			createContextMenu(event, menuItems);
		}
	});
	/*
	 * Splitter between the two task sub-panes: delegated, because the
	 * tasks pane markup is regenerated on every event refresh
	 */
	document.addEventListener('mousedown', function(e) {
		var rz = e.target.closest ? e.target.closest('.resizer-v') : null;
		if (!rz || !rz.previousElementSibling)
			return;
		e.preventDefault();
		sai_tt_split_begin(rz.previousElementSibling, e.clientX);
	});
	document.addEventListener('touchstart', function(e) {
		var rz = e.target.closest ? e.target.closest('.resizer-v') : null;
		if (!rz || !rz.previousElementSibling || e.touches.length !== 1)
			return;
		/*
		 * Claim the gesture: no pan of the surrounding scrollers, and
		 * no synthesized mousedown after touchend starting a second drag
		 */
		e.preventDefault();
		sai_tt_split_begin(rz.previousElementSibling, e.touches[0].clientX);
	}, { passive: false });

	const resizer = document.getElementById('resizer');
	if (resizer) {
		const rightPane = resizer.nextElementSibling;

		let x = 0;
		let rightWidth = 0;
		let lastVisible = -1;

		const onMouseMove = (e) => {
			const dx = x - e.clientX;
			let newRightWidth = rightWidth + dx;
			if (newRightWidth < 20) newRightWidth = 0;
			rightPane.style.flex = `0 0 ${newRightWidth}px`;
			let visible = newRightWidth > 0 ? 1 : 0;
			if (visible !== lastVisible) {
				lastVisible = visible;
				sai.send(JSON.stringify({ schema: "com.warmcat.sai.builder_visibility", visible: visible }));
			}
		};

		const onMouseUp = () => {
			document.removeEventListener('mousemove', onMouseMove);
			document.removeEventListener('mouseup', onMouseUp);
			localStorage.setItem('sai-right-pane-flex', rightPane.style.flex);
		};

		const onMouseDown = (e) => {
			x = e.clientX;
			rightWidth = rightPane.getBoundingClientRect().width;
			lastVisible = rightWidth > 0 ? 1 : 0;
			document.addEventListener('mousemove', onMouseMove);
			document.addEventListener('mouseup', onMouseUp);
		};

		const onTouchMove = (e) => {
			if (e.touches.length === 1) {
				const dx = x - e.touches[0].clientX;
				let newRightWidth = rightWidth + dx;
				if (newRightWidth < 20) newRightWidth = 0;
				rightPane.style.flex = `0 0 ${newRightWidth}px`;
				e.preventDefault();
				let visible = newRightWidth > 0 ? 1 : 0;
				if (visible !== lastVisible) {
					lastVisible = visible;
					sai.send(JSON.stringify({ schema: "com.warmcat.sai.builder_visibility", visible: visible }));
				}
			}
		};

		const onTouchEnd = () => {
			document.removeEventListener('touchmove', onTouchMove);
			document.removeEventListener('touchend', onTouchEnd);
			localStorage.setItem('sai-right-pane-flex', rightPane.style.flex);
		};

		const onTouchStart = (e) => {
			if (e.touches.length === 1) {
				x = e.touches[0].clientX;
				rightWidth = rightPane.getBoundingClientRect().width;
				lastVisible = rightWidth > 0 ? 1 : 0;
				document.addEventListener('touchmove', onTouchMove, { passive: false });
				document.addEventListener('touchend', onTouchEnd);
			}
		};

		resizer.addEventListener('mousedown', onMouseDown);
		resizer.addEventListener('touchstart', onTouchStart);
	}

	const savedTasksHeight = localStorage.getItem('sai-tasks-height');
	if (savedTasksHeight) {
		const tasksSection = document.getElementById('sai_event_tasks');
		if (tasksSection) {
			tasksSection.style.flex = savedTasksHeight;
		}
	}

	const resizerH = document.getElementById('resizer_h');
	if (resizerH) {
		const tasksSection = resizerH.previousElementSibling;

		let y = 0;
		let tasksHeight = 0;

		const onMouseMoveH = (e) => {
			const dy = e.clientY - y;
			const newHeight = tasksHeight + dy;
			tasksSection.style.flex = `0 0 ${newHeight}px`;
		};

		const onMouseUpH = () => {
			document.removeEventListener('mousemove', onMouseMoveH);
			document.removeEventListener('mouseup', onMouseUpH);
			localStorage.setItem('sai-tasks-height', tasksSection.style.flex);
		};

		const onMouseDownH = (e) => {
			y = e.clientY;
			tasksHeight = tasksSection.getBoundingClientRect().height;
			document.addEventListener('mousemove', onMouseMoveH);
			document.addEventListener('mouseup', onMouseUpH);
		};

		const onTouchMoveH = (e) => {
			if (e.touches.length === 1) {
				const dy = e.touches[0].clientY - y;
				const newHeight = tasksHeight + dy;
				tasksSection.style.flex = `0 0 ${newHeight}px`;
				e.preventDefault();
			}
		};

		const onTouchEndH = () => {
			document.removeEventListener('touchmove', onTouchMoveH);
			document.removeEventListener('touchend', onTouchEndH);
			localStorage.setItem('sai-tasks-height', tasksSection.style.flex);
		};

		const onTouchStartH = (e) => {
			if (e.touches.length === 1) {
				y = e.touches[0].clientY;
				tasksHeight = tasksSection.getBoundingClientRect().height;
				document.addEventListener('touchmove', onTouchMoveH, { passive: false });
				document.addEventListener('touchend', onTouchEndH);
			}
		};

		resizerH.addEventListener('mousedown', onMouseDownH);
		resizerH.addEventListener('touchstart', onTouchStartH);
	}
}, false);

}());
