const SAI_JS_API_VERSION = 3;

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

var logs = "", redpend = 0, gitohashi_integ = 0, authd = 0, exptimer, auth_user = "",
	logAnsiState = {}, logs_pending = "", lines_pending = "", times_pending = "",
	ongoing_task_activities = {}, last_log_timestamp = 0, spreadsheet_data_cache = {}, loadreport_data_cache = {},
	fadingTasks = new Map();

/* Global caches for reconcilation */
var pcon_topology = {};
var pcon_energy_cache = {};
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

    let stateClass = pcon.on ? "pcon-on" : "pcon-off";
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
		const el = document.getElementById("taskstate_" + uuid);
		if (el) {
			const cat = ongoing_task_activities[uuid];
			el.classList.remove("activity-1", "activity-2", "activity-3");
			if (cat > 0) {
				el.classList.add("activity-" + cat);
			}
		}
	}
}

function expiry()
{
	location.reload();
}

function san(s)
{
	if (s.search("<") !== -1)
		return "invalid string";

	return s;
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

function ansiToHtml(text, state) {
    const classMap = {
        '1': 'ansi-bold', '4': 'ansi-underline',
        '30': 'ansi-fg-black', '31': 'ansi-fg-red', '32': 'ansi-fg-green', '33': 'ansi-fg-yellow', '34': 'ansi-fg-blue', '35': 'ansi-fg-magenta', '36': 'ansi-fg-cyan', '37': 'ansi-fg-white',
        '40': 'ansi-bg-black', '41': 'ansi-bg-red', '42': 'ansi-bg-green', '43': 'ansi-bg-yellow', '44': 'ansi-bg-blue', '45': 'ansi-bg-magenta', '46': 'ansi-bg-cyan', '47': 'ansi-bg-white',
    };

    // Ensure state is a valid object
    state = state || {};
    let currentClasses = new Set(state.classes || []);

    const parts = text.split(/(\u001b\[[\d;]*m)/);
    let html = '';

    for (const part of parts) {
        if (!part) continue;

        if (part.startsWith('\u001b[')) { // It's an ANSI code
            const codes = part.substring(2, part.length - 1).split(';');

            if (codes.length === 1 && (codes[0] === '0' || codes[0] === '')) {
                // Reset
                currentClasses.clear();
            } else {
                for (const code of codes) {
                    if (classMap[code]) {
                        // Handle foreground/background colors: remove old before adding new
                        if (code >= 30 && code <= 37) {
                            currentClasses.forEach(c => { if (c.startsWith('ansi-fg-')) currentClasses.delete(c); });
                        }
                        if (code >= 40 && code <= 47) {
                            currentClasses.forEach(c => { if (c.startsWith('ansi-bg-')) currentClasses.delete(c); });
                        }
                        currentClasses.add(classMap[code]);
                    }
                }
            }
        } else { // It's plain text
            const sanitizedPart = hsanitize(part);
            if (currentClasses.size > 0) {
                html += `<span class="${Array.from(currentClasses).join(' ')}">${sanitizedPart}</span>`;
            } else {
                html += sanitizedPart;
            }
        }
    }

    return {
        html: html,
        newState: { classes: Array.from(currentClasses) }
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

    tr.innerHTML = `<td>${s1}</td>` +
                   `<td>${agify(now_ut, task.started)} ago</td>` +
                   `<td><a href="index.html?task=${hsanitize(task.task_uuid)}">${hsanitize(task.task_name)}</a></td>`;
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
    tr.innerHTML = `<td>${s1}</td>` +
                   `<td>${agify(now_ut, task.started)} ago</td>` +
                   `<td><a href="index.html?task=${hsanitize(task.task_uuid)}">${hsanitize(task.task_name)}</a></td>`;
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

    for (const row of rows) {
        tbody.appendChild(row);
    }
}

var pos = 0, lli = 1, lines = "", times = "", locked = 1, tfirst = 0,
		cont = [ 0, 0, 0, 0, 0];

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
	window.setTimeout(aging, next * 1000);
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
		san(t.t.platform) + "</span>&nbsp;";
	if (authd && t.t.state != 0 && t.t.state != 3 && t.t.state != 4 && t.t.state != 5)
		s += "<img class=\"rebuild\" alt=\"stop build\" src=\"stop.svg\" " +
			"id=\"stop-" + san(t.t.uuid) + "\">&nbsp;";
	if (authd)
		s += "<img class=\"rebuild\" alt=\"rebuild\" src=\"rebuild.png\" " +
			"id=\"rebuild-" + san(t.t.uuid) + "\">&nbsp;" +
			sai_stateful_taskname(t.t.state, t.t.taskname, 1);

	if (t.t.builder_name) {
		var now_ut = Math.round((new Date().getTime() / 1000));

		s += "&nbsp;&nbsp;<span class=\"ti5\"><img class=\"bico\" src=\"/sai/builder-instance.png\">&nbsp;" +
			san(t.t.builder_name) + "</span>";
		if (t.t.started)
		/* started is a unix time, in seconds */
		s += ", <span class=\"ti5\"> " +
		     agify(now_ut, t.t.started) + " ago, Dur: " +
		     (t.t.duration ? t.t.duration / 1000000 :
			now_ut - t.t.started).toFixed(1) +
			"s</span><div id=\"sai_arts\"></div><div id=\"metrics-summary-" + san(t.t.uuid) + "\"></div>";
		sai_arts = "";
	}

	s += "</td></tr>";

	s += "</td></tr></table></table>";

	return s;
}

function update_summary_and_progress(event_uuid) {
    var sumbs = document.getElementById("sumbs-" + event_uuid);
    if (!sumbs)
        return;

    var summary = summarize_build_situation(event_uuid);
    var summary_html = summary.text;

    if (summary.total > 0) {
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
            "<div class=\"progress-bar-pending " + pending_cls + "\"></div>" +
            "<div class=\"progress-bar-ongoing " + ongoing_cls + "\"></div>" +
            "<div class=\"progress-bar-failed float-right " + bad_cls + "\"></div>" +
            "</div>";
    }
    sumbs.innerHTML = summary_html;
}

function summarize_build_situation(event_uuid)
{
	var good = 0, bad = 0, total = 0, ongoing = 0, pending = 0,
		roo = document.getElementById("taskcont-" + event_uuid),
		same;

	if (!roo)
		return { text: "" };

	same = roo.querySelectorAll(".taskstate");
	if (same)
		total = same.length;
	same = roo.querySelectorAll(".taskstate0");
	if (same)
		pending = same.length;
	same = roo.querySelectorAll(".taskstate1");
	if (same)
		ongoing += same.length;
	same = roo.querySelectorAll(".taskstate2");
	if (same)
		ongoing += same.length;
	same = roo.querySelectorAll(".taskstate3");
	if (same)
		good = same.length;
	same = roo.querySelectorAll(".taskstate4");
	if (same)
		bad += same.length;
	same = roo.querySelectorAll(".taskstate5");
	if (same)
		bad += same.length; // treat cancelled as bad
	same = roo.querySelectorAll(".taskstate6");
	if (same)
		ongoing += same.length;

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
	if (reset_all_icon && !gitohashi_integ && authd) {
		s += "<br><img class=\"rebuild\" alt=\"rebuild all\" src=\"/sai/rebuild.png\" " +
			"id=\"rebuild-ev-" + san(e.uuid) + "\">&nbsp;";
		s += "<img class=\"rebuild\" alt=\"delete event\" src=\"/sai/delete.png\" " +
				"id=\"delete-ev-" + san(e.uuid) + "\">";
	}
	s += "</td>";

	if (!gitohashi_integ) {
		s +=
		"<td><table class=\"nomar\">" +
		"<tr><td class=\"nomar\" colspan=2>" +
		"<span class=\"e1\">" + san(e.repo_name);
		if (e.sec)
			s += " <img class=\"bico\" src=\"/sai/locked.svg\">";
		s += "</span></td></tr><tr><td class=\"nomar\" colspan=2><span class=\"e2\">";

		if (e.ref.substr(0, 11) === "refs/heads/") {
			s += "<img class=\"branch\">" +
				san(e.ref.substr(11));
		} else
			if (e.ref.substr(0, 10) === "refs/tags/") {
				s += "<img class=\"tag\">" +
					san(e.ref.substr(10));
			} else
				s += san(e.ref);

		s += "</span></td></tr><tr><td class=\"nomar e6\">" +
		        san(e.hash.substr(0, 8)) +
		     "</td><td class=\"e6 nomar\">" +
		     agify(now_ut, e.created) + "</td></tr>";
		 s += "</table>" +
		     "</td>";
	} else {
		s +="<td><table><tr><td class=\"e6 nomar\">" + san(e.hash.substr(0, 8)) + " " + agify(now_ut, e.created) +
		     "</td></tr><tr><td class=\"nomar e6\" id=\"sumbs-" + e.uuid + "\"></td></tr>" +
		     "</table></td>";
	}
	s += "</tr><tr><td class=\"nomar e6\" colspan=\"2\" id=\"sumbs-" + e.uuid +"\"></td></tr></table>";

	return s;
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

		for (q = 0; q < o.t.length; q++) {
			var t = o.t[q];

			if (t.taskname !== ctn) {
				if (ctn !== "") {
					s += "<div class=\"ib\"><table class=\"nomar\">" +
					     "<tr><td class=\"tn\">" + ctn +
					     "</td><td class=\"keepline\">" + s1 +
					     "</td></tr></table></div>";
					s1 = "";
				}
				ctn = t.taskname;
			}

			s1 += "<div id=\"taskstate_" + t.uuid + "\" class=\"taskstate taskstate" + t.state +
				"\" data-event-uuid=\"" + san(e.uuid) + "\" data-platform=\"" + san(t.platform) +
				"\" data-rebuildable=\"" + t.rebuildable + "\">";
			s1 += "<a href=\"/sai/index.html?task=" + t.uuid + "\">" +
				sai_plat_icon(t.platform, 0) + "</a>";
			s1 += "</div>";
		}

		if (ctn !== "") {
			s += "<div class=\"ib\"><table class=\"nomar\">" +
				"<tr><td class=\"tn\">" + ctn +
				"<td class=\"keepline\">" + s1 +
				"</td></tr></table></div>";
		}

		s += "</td></tr></table>";
		if (gitohashi_integ)
			s += "</div>";
		s += "</td>";
	}

	s += "</tr>";

	return s;
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

function refresh_state(task_uuid, task_state)
{
	var tsi = document.getElementById("taskstate_" + task_uuid);

	if (tsi) {
		tsi.classList.remove("taskstate0");
		tsi.classList.remove("taskstate1");
		tsi.classList.remove("taskstate2");
		tsi.classList.remove("taskstate3");
		tsi.classList.remove("taskstate4");
		tsi.classList.remove("taskstate5");
		tsi.classList.remove("taskstate6");
		tsi.classList.remove("taskstate7");
		tsi.classList.remove("taskstate10");
		tsi.classList.add("taskstate" + task_state);
		// console.log("refresh_state  taskstate" + task_state);
	}
}

function after_delete() {
	location.reload();
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
	if (!plat.online)
		platDiv.className += " offline";
	else {
		if (!plat.power_managed)
			platDiv.className += " power-unmanaged";
		else
			if (plat.stay_on !== 0)
				platDiv.className += " power-stay";
			else
				platDiv.className += " power-stay-dep";
	}
	if (plat.powering_up)
		platDiv.className += " powering-up";
	if (plat.powering_down)
		platDiv.className += " powering-down";

	platDiv.id = "binfo-" + plat.name;
	platDiv.title = plat.platform + "@" + plat.name.split('.')[0] + " / " + plat.peer_ip;

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
	innerHTML += `${plat.peer_ip}` + "  " + plat.stay_on;
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
		{ label: `<b>SAI:</b> ${plat.sai_hash}` },
		{ label: `<b>LWS:</b> ${plat.lws_hash}` },
	];

	if (plat.power_managed && authd) {
		if (plat.stay_on !== 0) {
			menuItems.push({
				label: "Release Stay",
				callback: () => {
					const stayMsg = {
						schema: "com.warmcat.sai.stay",
						builder_name: plat.name.split('.')[0],
						stay_on: 0
					};
					sai.send(JSON.stringify(stayMsg));
				}
			});
		} else {
			menuItems.push({
				label: "Stay On",
				callback: () => {
					const stayMsg = {
						schema: "com.warmcat.sai.stay",
						builder_name: plat.name.split('.')[0],
						stay_on: 1
					};
					sai.send(JSON.stringify(stayMsg));
				}
			});
		}
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

    let stateClass = pcon.on ? "pcon-on" : "pcon-off";
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
        { label: `<b>PCON:</b> ${pcon.name}` }
    ];

    if (authd) {
        if (pcon.on) {
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
//	if (s1.split("?"))
//	s1 = s1.split("?")[0];
	console.log(s1);
	sai = new WebSocket(s1, "com-warmcat-sai");

	try {
		sai.onopen = function() {
			var overlay = document.querySelector(".overlay");
			if (overlay) {
				overlay.parentNode.removeChild(overlay);
			}
			document.body.classList.remove("overlay-active");

			var par = new URLSearchParams(window.location.search),
				tid, eid;
			tid = par.get('task');
			eid = par.get('event');


			if (tid) {
				/*
				 * We're being the page monitoring / reporting
				 * on what happened with a specific task... ask
				 * about the specific task on the ws link
				 */

				 console.log("tid " + tid);

				 sai.send("{\"schema\":" +
					  "\"com.warmcat.sai.taskinfo\"," +
					  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
					  "\"logs\": 1," +
					  "\"last_log_ts\":" + last_log_timestamp + "," +
					  "\"task_hash\":" +
					  JSON.stringify(tid) + "}");

				 return;
			}

			if (eid) {
				/*
				 * We're being the page monitoring / reporting
				 * on what happened with a specific event... ask
				 * about the specific event on the ws link
				 */

				 console.log("eid " + eid);

				 sai.send("{\"schema\":" +
					  "\"com.warmcat.sai.eventinfo\"," +
					  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
					  "\"event_hash\":" +
					  JSON.stringify(eid) + "}");

				 return;
			}

			/*
			 * request the overview schema
			 */

			 sai.send("{\"schema\":" +
				  "\"com.warmcat.sai.taskinfo\", \"js_api_version\": " + SAI_JS_API_VERSION + "}");
		};

		sai.onmessage = function got_packet(msg) {
			var u, ci, n;
			var now_ut = Math.round((new Date().getTime() / 1000));

		//	console.log(msg.data);
		//	if (msg.data.length < 10)
		//		return;
		try {
			jso = JSON.parse(msg.data);
		} catch {
			console.log("Bad JSON received:");
			console.log(msg.data);
			return
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
//							stats.textContent = `${d.voltage_v}V ${d.active_power_w}W ${d.current_ma}mA today:${(d.energy_today_wh/1000).toFixed(3)}kWh`;
							if (d.voltage_v < 70)
								stats.textContent = "unpowered";
							else if (!d.active_power_w)
								stats.textContent = "OFF";
							else
								stats.textContent = `${d.active_power_w}W`;
						}
					});
				}
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

			case "sai.warmcat.com.overview":
				/*
				 * Sent with an array of e[] to start, but also
				 * can send a single e[] if it just changed
				 * state
				 */
				s = "<table>";

				authd = jso.authorized;
				if (jso.authorized === 0) {
					if (document.getElementById("creds"))
						document.getElementById("creds").classList.remove("hide");
					if (document.getElementById("logout"))
						document.getElementById("logout").classList.add("hide");
				}
				if (jso.authorized === 1) {
					if (document.getElementById("creds"))
						document.getElementById("creds").classList.add("hide");
					if (document.getElementById("logout"))
						document.getElementById("logout").classList.remove("hide");
					if (jso.auth_user)
						auth_user = jso.auth_user;
					if (jso.auth_secs) {
						var now_ut = Math.round((new Date().getTime() / 1000));
						clearTimeout(exptimer);
						exptimer = window.setTimeout(expiry, 1000 * jso.auth_secs);
						if (document.getElementById("remauth"))
							document.getElementById("remauth").innerHTML =
								san(auth_user) + " " + agify(now_ut, now_ut + jso.auth_secs);
					}
				}

				/*
				 * Update existing?
				 */

				// console.log("jso.overview.length " + jso.overview.length);

				if (jso.overview.length == 1 &&
				    document.getElementById("esr-" + jso.overview[0].e.uuid)) {
					/* this is just the summary box, not the tasks */
					document.getElementById("esr-" + jso.overview[0].e.uuid).innerHTML =
						sai_event_summary_render(jso.overview[0], now_ut, 1);

					/* if the task status icons exist, update their state */

					for (n = jso.overview[0].t.length - 1; n >= 0; n--)
						refresh_state(jso.overview[0].t[n].uuid, jso.overview[0].t[n].state);

					update_summary_and_progress(jso.overview[0].e.uuid);

					aging();
				} else
				{
					/*
					 * display events wholesale
					 */
					if (jso.overview.length) {
						for (n = jso.overview.length - 1; n >= 0; n--)
							s += sai_event_render(jso.overview[n], now_ut, 1);

						s = s + "</table>";

						if (document.getElementById("sai_sticky"))
							document.getElementById("sai_sticky").innerHTML = s;

						for (n = jso.overview.length - 1; n >= 0; n--) {
							document.getElementById("esr-" + jso.overview[n].e.uuid).innerHTML =
								sai_event_summary_render(jso.overview[n], now_ut, 1);

							update_summary_and_progress(jso.overview[n].e.uuid);
						}
						aging();
					}

					if (gitohashi_integ && document.getElementById("gitohashi_sai_icon")) {
						var integ_state = 0;
						document.getElementById("gitohashi_sai_icon").addEventListener("mouseenter", function( event ) {
							document.getElementById("gitohashi_sai_icon").style.zIndex = 1999;
							document.getElementById("gitohashi_sai_details").style.zIndex = 2000;
							document.getElementById("gitohashi_sai_details").style.opacity = 1.0;
							integ_state = 1;
						}, false);

						document.getElementById("gitohashi_sai_details").addEventListener("mouseout", function( event ) {
							var e = event.toElement || event.relatedTarget;
							while (e && e.parentNode && e.parentNode != window) {
							    if (e.parentNode == this ||  e == this) {
							        if (e.preventDefault)
									e.preventDefault();
							        return false;
							    }
							    e = e.parentNode;
							}
							document.getElementById("gitohashi_sai_details").style.opacity = 0.0;
							document.getElementById("gitohashi_sai_details").style.zIndex = -1;
							document.getElementById("gitohashi_sai_icon").style.zIndex = 2001;
						}, true);

						aging();
					}
				}

				if (jso.overview.length)
					for (n = jso.overview.length - 1; n >= 0; n--) {
						if (document.getElementById("rebuild-ev-" + san(jso.overview[n].e.uuid)))
							document.getElementById("rebuild-ev-" + san(jso.overview[n].e.uuid)).
								addEventListener("click", function(e) {
					console.log(e);
						var rs= "{\"schema\":" +
						 "\"com.warmcat.sai.eventreset\"," +
						 "\"uuid\": " +
							JSON.stringify(san(e.srcElement.id.substring(11))) + "}";

						console.log(rs);
						sai.send(rs);
					});
					if (document.getElementById("delete-ev-" + san(jso.overview[n].e.uuid)))
						document.getElementById("delete-ev-" + san(jso.overview[n].e.uuid)).
							addEventListener("click", function(e) {
					console.log(e);
						var rs= "{\"schema\":" +
						 "\"com.warmcat.sai.eventdelete\"," +
						 "\"uuid\": " +
							JSON.stringify(san(e.srcElement.id.substring(10))) + "}";

						console.log(rs);
						sai.send(rs);
						setTimeout(after_delete, 750);
					});
				}
				break;

			case "com.warmcat.sai.taskinfo":

				if (!jso.t)
					break;

				authd = jso.authorized;
				if (jso.authorized === 0) {
					if (document.getElementById("creds"))
						document.getElementById("creds").classList.remove("hide");
					if (document.getElementById("logout"))
						document.getElementById("logout").classList.add("hide");
				}
				if (jso.authorized === 1) {
					if (document.getElementById("creds"))
						document.getElementById("creds").classList.add("hide");
					if (document.getElementById("logout"))
						document.getElementById("logout").classList.remove("hide");
					if (jso.auth_user)
						auth_user = jso.auth_user;
					if (jso.auth_secs) {
						var now_ut = Math.round((new Date().getTime() / 1000));
						clearTimeout(exptimer);
						exptimer = window.setTimeout(expiry, 1000 * jso.auth_secs);
						if (document.getElementById("remauth"))
							document.getElementById("remauth").innerHTML =
								san(auth_user) + " " + agify(now_ut, now_ut + jso.auth_secs);
					}
				}

				/*
				 * We get told about changes to any task state,
				 * it's up to us to figure out if the page we
				 * showed should display the update and in what
				 * form.
				 *
				 * We make sure the div containing the task info
				 * has a special ID depending on if it's shown
				 * as a tuple or as extended info
				 *
				 * First see if it appears as a tuple, and if
				 * so, let's just update that
				 */

				if (document.getElementById("taskstate_" + jso.t.uuid)) {
					console.log("found taskstate_" + jso.t.uuid);
					refresh_state(jso.t.uuid, jso.t.state);

					update_summary_and_progress(jso.t.uuid.substring(0, 32));

				} else

					/* update task summary if shown anywhere */

					if (document.getElementById("taskinfo-" + jso.t.uuid)) {
						console.log("FOUND taskinfo-" + jso.t.uuid);
						document.getElementById("taskinfo-" + jso.t.uuid).innerHTML = sai_taskinfo_render(jso);
						if (document.getElementById("esr-" + jso.e.uuid))
							document.getElementById("esr-" + jso.e.uuid).innerHTML =
								sai_event_summary_render(jso, now_ut, 1);
						update_summary_and_progress(jso.e.uuid);

					} else {

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
						    document.getElementById("sai_sticky"))
							document.getElementById("sai_sticky").innerHTML =
								"<div class=\"taskinfo\" id=\"taskinfo-" +
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

						if (document.getElementById("esr-" + jso.e.uuid))
							document.getElementById("esr-" + jso.e.uuid).innerHTML =
								sai_event_summary_render(jso, now_ut, 1);

					}
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

								/*
								 * and immediately re-request the task info, so we can get
								 * the new logs
								 */
								var tid = san(e.srcElement.id.substring(8));
								var rq = "{\"schema\":" +
									  "\"com.warmcat.sai.taskinfo\"," +
									  "\"js_api_version\": " + SAI_JS_API_VERSION + "," +
									  "\"logs\": 1," +
									  "\"last_log_ts\":" + last_log_timestamp + "," +
									  "\"task_hash\":" +
									  JSON.stringify(tid) + "}";

								console.log(rq);
								sai.send(rq);

								document.getElementById("dlogsn").innerHTML = "";
								document.getElementById("dlogst").innerHTML = "";
								document.getElementById("logs").innerHTML = "";
								lines = times = logs = "";
								lines_pending = times_pending = logs_pending = "";
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
				}
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

				sai_arts += "<div class=\"sai_arts\"><img src=\"artifact.svg\">&nbsp;<a href=\"artifacts/" +
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

			case "com.warmcat.sai.unauthorized":
				location.reload();
				break;

			case "com-warmcat-sai-logs":
				try {
					var s1 = decodeURIComponent(escape(atob(jso.log))),
					    ansiResult = ansiToHtml(s1, logAnsiState),
					    s = ansiResult.html, li,
					    en = "", yo, dh, ce, tn = "";
					logAnsiState = ansiResult.newState;
				} catch (e) {
					break;
				}

				if (!tfirst)
					tfirst = jso.timestamp;

				last_log_timestamp = jso.timestamp;

				li = (s1.match(/\n/g)||[]).length;

				switch (jso.channel) {
				case 1:
					logs += s; logs_pending += s;
					break;
				case 2:
					logs += "<span class=\"stderr\">" + s +
							"</span>";
					logs_pending += "<span class=\"stderr\">" + s +
							"</span>";
					break;
				case 3:
					logs += "<span class=\"saibuild\">\u{25a0} " + s +
							"</span>";
					logs_pending += "<span class=\"saibuild\">\u{25a0} " + s +
							"</span>";
					break;
				case 4:
					logs += "<span class=\"tty0\">" + s +
							"</span>";
					logs_pending += "<span class=\"tty0\">" + s +
							"</span>";
					break;
				default:
					logs += "<span class=\"tty1\">" + s +
							"</span>";
					logs_pending += "<span class=\"tty1\">" + s +
							"</span>";


				}

				if (cont && !cont[jso.channel] && jso.len)
					tn = ((jso.timestamp - tfirst) / 1000000).toFixed(4);

				if (cont)
				cont[jso.channel] = (li == 0);

				while (li--) {
					en += "<a id=\"#sn" + lli +
						"\" href=\"#sn" + lli + "\">" +
						lli + "</a><br>";
					tn += "<br>"
					lli++;
				}

				lines += en; lines_pending += en;
				times += tn; times_pending += tn;

				if (!redpend) {
					redpend = 1;
					setTimeout(function() {
						const rightPane = document.querySelector('.right-pane');
						redpend = 0;
						if (rightPane)
							locked = rightPane.scrollHeight -
								rightPane.clientHeight <=
								rightPane.scrollTop + 1;

						if (document.getElementById("logs")) {
							if (logs_pending) {
								document.getElementById("logs").insertAdjacentHTML('beforeend', logs_pending);
								logs_pending = "";
							}

							if (document.getElementById("dlogsn") && lines_pending) {
								document.getElementById("dlogsn").insertAdjacentHTML('beforeend', lines_pending);
								lines_pending = "";
							}

							if (document.getElementById("dlogst") && times_pending) {
								document.getElementById("dlogst").insertAdjacentHTML('beforeend', times_pending);
								times_pending = "";
							}
						}

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
			var overlay = document.createElement("div");
			overlay.className = "overlay";
			document.body.appendChild(overlay);
			document.body.classList.add("overlay-active");

			console.log("WebSocket closed. Code:", ev.code, "Reason:", ev.reason);
			myVar = setTimeout(ws_open_sai, 4000);
		};
	} catch(exception) {
		alert("<p>Error" + exception);
	}
}

function post_login_form()
{
	var xhr = new XMLHttpRequest(), s ="", q = window.location.pathname;

	s = "----boundo\x0d\x0acontent-disposition: form-data; name=\"lname\"\x0d\x0a\x0d\x0a" +
		document.getElementById("lname").value +
	    "\x0d\x0a----boundo\x0d\x0acontent-disposition: form-data; name=\"lpass\"\x0d\x0a\x0d\x0a" +
		document.getElementById("lpass").value +
	    "\x0d\x0a----boundo\x0d\x0acontent-disposition: form-data; name=\"success_redir\"\x0d\x0a\x0d\x0a" +
		document.getElementById("success_redir").value +
	    "\x0d\x0a----boundo--";

	if (q.length > 10 && q.substring(q.length - 10) == "index.html")
		q = q.substring(0, q.length - 10);
	xhr.open("POST", q + "login", true);
	xhr.setRequestHeader( 'content-type', "multipart/form-data; boundary=--boundo");

	console.log(s.length +" " + s);

	xhr.onload = function (e) {
	  if (xhr.readyState === 4) {
	    if (xhr.status === 200 || xhr.status == 303) {
	      console.log(xhr.responseText);
		location.reload();
	    } else {
	      console.error(xhr.statusText);
	    }
	  }
	};
	xhr.onerror = function (e) {
	  console.error(xhr.statusText);
	};

	xhr.send(s);

	return false;
}

/* stuff that has to be delayed until all the page assets are loaded */

window.addEventListener("load", function() {

	const savedFlex = localStorage.getItem('sai-left-pane-flex');
	if (savedFlex) {
		const leftPane = document.querySelector('.left-pane');
		if (leftPane) {
			leftPane.style.flex = savedFlex;
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

	/* login form hidden success redirect */
	if (document.getElementById("success_redir"))
		document.getElementById("success_redir").value =
			window.location.href;
	ws_open_sai();
	aging();

	if (document.getElementById("login-button")) {
		document.getElementById("login-button").addEventListener("click", post_login_form);
		document.getElementById("logout-button").addEventListener("click", post_login_form);
	}

	setInterval(function() {
		update_task_activities();

	    var locked = document.body.scrollHeight -
		document.body.clientHeight <= document.body.scrollTop + 1;

	    if (locked)
	     document.body.scrollTop = document.body.scrollHeight -
		document.body.clientHeight;

	}, 500)

	const stickyEl = document.getElementById("sai_sticky");
	if (stickyEl) {
		stickyEl.addEventListener("contextmenu", function(event) {
			let target = event.target;
			let taskDiv = null;

			// find the taskstate div parent
			while (target && target.id !== "sai_sticky") {
				if (target.classList && target.classList.contains("taskstate")) {
					taskDiv = target;
					break;
				}
				target = target.parentElement;
			}

			if (taskDiv && authd) {
				event.preventDefault();

				const taskUuid = taskDiv.id.substring(10);
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

				const isFinalState = ["taskstate3", "taskstate4", "taskstate5", "taskstate7"].some(s => taskDiv.classList.contains(s));

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
	}
	const resizer = document.getElementById('resizer');
	if (resizer) {
		const leftPane = resizer.previousElementSibling;

		let x = 0;
		let leftWidth = 0;

		const onMouseMove = (e) => {
			const dx = e.clientX - x;
			const newLeftWidth = leftWidth + dx;
			leftPane.style.flex = `0 0 ${newLeftWidth}px`;
		};

		const onMouseUp = () => {
			document.removeEventListener('mousemove', onMouseMove);
			document.removeEventListener('mouseup', onMouseUp);
			localStorage.setItem('sai-left-pane-flex', leftPane.style.flex);
		};

		const onMouseDown = (e) => {
			x = e.clientX;
			leftWidth = leftPane.getBoundingClientRect().width;
			document.addEventListener('mousemove', onMouseMove);
			document.addEventListener('mouseup', onMouseUp);
		};

		resizer.addEventListener('mousedown', onMouseDown);
	}
}, false);

}());
