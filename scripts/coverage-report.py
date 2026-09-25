#!/usr/bin/env python3
#
# Summarize gcov-format coverage of a build tree after ctest has run in it.
#
# Run it from the build directory of a tree configured with
# -DLWS_WITH_GCOV=1 (gcc or clang): every test process leaves .gcda counters
# next to its objects when it exits.  The script takes the compiler and the
# source directory from CMakeCache.txt, runs gcov (or llvm-cov gcov for a
# clang-built tree) over every .gcno under the build directory, merges the
# results per source file, and prints
#
#  - overall line and function coverage of the library sources,
#  - a per-directory table, worst first,
#  - every function that was built but has no or thin line coverage, worst
#    first.
#
# It only reports; it never fails the build.  Missing tools or unreadable
# data files are printed as warnings and the exit code is still 0.
#
#   cd build && ../scripts/coverage-report.py [--include PREFIX]...
#                      [--threshold PCT] [--limit N] [--json]
#
# LWS_GCOV in the environment names the reader to use instead of the one
# matched to the compiler, eg LWS_GCOV="llvm-cov gcov".
#
# `make coverage` in a gcov-instrumented tree runs it from the right place.

import argparse, collections, concurrent.futures, glob, gzip, json, os, re
import shutil, subprocess, sys, tempfile

JSON_OUT = "coverage-summary.json"


def cmake_cache(keys):
	"""The requested CMakeCache.txt entries of the current directory."""
	found = {}
	try:
		with open("CMakeCache.txt") as fp:
			for line in fp:
				k, _, v = line.partition("=")
				k = k.split(":")[0]
				if k in keys:
					found[k] = v.strip()
	except OSError:
		pass

	return found


def first_available(cands):
	for c in cands:
		if shutil.which(c[0]):
			return c

	return None


def prog_name(compiler, name):
	"""Ask the compiler where its companion tool lives, or ''."""
	try:
		p = subprocess.run([compiler, "-print-prog-name=" + name],
				   capture_output=True, text=True).stdout.strip()
	except OSError:
		return ""

	return p if os.sep in p else ""


def clang_reader(compiler):
	"""clang's gcov files need llvm-cov; gcc's gcov rejects them."""
	cands = []
	p = prog_name(compiler, "llvm-cov")
	if p:
		cands.append([p, "gcov"])
	cands.append(["llvm-cov", "gcov"])
	cands += [["llvm-cov-%d" % v, "gcov"] for v in range(40, 9, -1)]

	return first_available(cands)


def gcc_reader(compiler):
	cands = []
	p = prog_name(compiler, "gcov")
	if p:
		cands.append([p])
	cands.append(["gcov"])

	return first_available(cands)


def find_tool(compiler):
	"""Pick the gcov reader that matches the compiler that made the .gcno."""
	explicit = os.environ.get("LWS_GCOV")
	if explicit:
		return explicit.split()

	if "clang" in os.path.basename(compiler):
		return clang_reader(compiler)

	return gcc_reader(compiler)


def tool_mode(tool):
	"""'json' for gcc gcov >= 9 (--json-format), else 'text' (-i)."""
	if "llvm-cov" in os.path.basename(tool[0]):
		return "text"
	v = subprocess.run(tool + ["--version"], capture_output=True,
			   text=True).stdout
	m = re.search(r"\) (\d+)\.", v)
	if m and int(m.group(1)) >= 9:
		return "json"

	return "text"


class Cov:
	def __init__(self):
		# file -> { "lines": {line: count}, "funcs": {(name, start): [count, end]} }
		self.files = collections.defaultdict(
			lambda: {"lines": collections.Counter(), "funcs": {}})
		self.errors = []

	def add_func(self, f, name, start, end, count):
		d = self.files[f]["funcs"]
		k = (name, start)
		if k in d:
			d[k][0] += count
			d[k][1] = max(d[k][1], end)
		else:
			d[k] = [count, end]

	def add_line(self, f, line, count):
		self.files[f]["lines"][line] += count


def parse_json(path, cov, norm):
	with gzip.open(path, "rt") as fp:
		d = json.load(fp)
	for fl in d.get("files", []):
		f = norm(fl["file"])
		if not f:
			continue
		for fn in fl.get("functions", []):
			cov.add_func(f, fn["name"], fn["start_line"],
				     fn.get("end_line", fn["start_line"]),
				     fn.get("execution_count", 0))
		for ln in fl.get("lines", []):
			cov.add_line(f, ln["line_number"], ln.get("count", 0))


def parse_text_function(rest):
	"""'function:' payload -> (name, start, end, count), or None."""
	a = rest.split(",")
	if len(a) >= 4:		# gcc 8 / llvm-cov: start,end,count,name
		return ",".join(a[3:]), int(a[0]), int(a[1]), int(a[2])
	if len(a) == 3:		# gcc 7: start,count,name
		return a[2], int(a[0]), int(a[0]), int(a[1])

	return None


def parse_text(path, cov, norm):
	"""gcov 7/8 and llvm-cov gcov -i intermediate text format."""
	f = None
	with open(path, errors="replace") as fp:
		for line in fp:
			line = line.rstrip("\n")
			if line.startswith("file:"):
				f = norm(line[5:])
			elif not f:
				continue
			elif line.startswith("function:"):
				fn = parse_text_function(line[9:])
				if fn:
					cov.add_func(f, *fn)
			elif line.startswith("lcount:"):
				a = line[7:].split(",")
				if len(a) >= 2:
					cov.add_line(f, int(a[0]), int(a[1]))


def run_one(tool, mode, gcno, tmp):
	"""Run the reader on one .gcno in its own scratch dir, return outputs."""
	d = tempfile.mkdtemp(dir=tmp)
	flags = ["--json-format"] if mode == "json" else ["-i"]
	r = subprocess.run(tool + flags + ["-o", os.path.dirname(gcno), gcno],
			   cwd=d, capture_output=True, text=True)
	outs = glob.glob(os.path.join(d, "*.gcov.json.gz")) if mode == "json" \
		else glob.glob(os.path.join(d, "*.gcov"))
	err = None
	if r.returncode or not outs:
		err = "%s: rc %d: %s" % (gcno, r.returncode,
					 (r.stderr or r.stdout).strip()[:200])
	return outs, err


def find_gcnos(bdir):
	gcnos = []
	for root, _, files in os.walk(bdir):
		gcnos += [os.path.join(root, f) for f in files if f.endswith(".gcno")]

	return gcnos


def make_norm(bdir, sdir, incl):
	"""Map a reader's file path to a counted source-relative path, or None."""
	def norm(path):
		p = os.path.normpath(path)
		if not os.path.isabs(p):
			p = os.path.normpath(os.path.join(bdir, p))
		if not p.startswith(sdir + os.sep):
			return None
		rel = p[len(sdir) + 1:]
		for i in incl:
			if rel.startswith(i):
				return rel
		return None

	return norm


def collect(tool, mode, gcnos, norm):
	"""Run the reader over every .gcno and merge into one Cov."""
	cov = Cov()
	parse = parse_json if mode == "json" else parse_text
	tmp = tempfile.mkdtemp(prefix="lws-cov-")
	try:
		with concurrent.futures.ThreadPoolExecutor(
				max_workers=os.cpu_count() or 2) as ex:
			for outs, err in ex.map(
					lambda g: run_one(tool, mode, g, tmp), gcnos):
				if err:
					cov.errors.append(err)
				for o in outs:
					try:
						parse(o, cov, norm)
					except (OSError, ValueError, KeyError) as e:
						cov.errors.append("%s: %s" % (o, e))
	finally:
		shutil.rmtree(tmp, ignore_errors=True)

	return cov


def pct(n, d):
	return 100.0 * n / d if d else 0.0


def summarize(cov):
	"""Totals, per-directory counts and per-function line coverage."""
	funcs = []		# (pct, executed, total, file, start, name, count)
	dirs = collections.defaultdict(lambda: [0, 0, 0, 0])	# lines x/n, funcs x/n
	tot = [0, 0, 0, 0]
	for f, d in sorted(cov.files.items()):
		lines = d["lines"]
		nl = len(lines)
		ne = sum(1 for c in lines.values() if c)
		nf = len(d["funcs"])
		nfe = sum(1 for c, _ in d["funcs"].values() if c)
		for acc in (tot, dirs[os.path.dirname(f)]):
			acc[0] += ne; acc[1] += nl; acc[2] += nfe; acc[3] += nf
		for (name, start), (count, end) in d["funcs"].items():
			fl = [c for l, c in lines.items() if start <= l <= end]
			n = len(fl)
			e = sum(1 for c in fl if c)
			funcs.append((pct(e, n), e, n, f, start, name, count))

	return tot, dirs, funcs


def print_report(incl, tot, dirs, funcs, threshold, limit, errors):
	te, tl, tfe, tf = tot
	print()
	print("coverage: %s  lines %d / %d (%.1f%%)  functions %d / %d (%.1f%%)" %
	      (" ".join(i.rstrip("/") for i in incl), te, tl, pct(te, tl),
	       tfe, tf, pct(tfe, tf)))
	print()
	print("per directory, worst first:")
	for dname, (ne, nl, nfe, nf) in sorted(dirs.items(),
					       key=lambda kv: (pct(kv[1][0], kv[1][1]), kv[0])):
		print("  %5.1f%%  %6d / %6d lines  %4d / %4d functions  %s" %
		      (pct(ne, nl), ne, nl, nfe, nf, dname))

	thin = [x for x in funcs if x[0] < threshold]
	thin.sort(key=lambda x: (x[0], -x[2], x[3], x[4]))
	never = sum(1 for x in funcs if not x[6])
	print()
	print("functions below %.0f%% line coverage, worst first: %d of %d "
	      "(%d never executed)" % (threshold, len(thin), len(funcs), never))
	shown = thin[:limit] if limit else thin
	for p, e, n, f, start, name, _ in shown:
		print("  %5.1f%%  %4d / %4d  %s:%d %s" % (p, e, n, f, start, name))
	if len(shown) < len(thin):
		print("  ... %d more" % (len(thin) - len(shown)))

	if errors:
		print()
		print("coverage: %d objects could not be read (first few):" %
		      len(errors))
		for e in errors[:10]:
			print("  ", e)

	return thin


def write_json(tot, dirs, thin):
	with open(JSON_OUT, "w") as fp:
		json.dump({
			"lines": [tot[0], tot[1]], "functions": [tot[2], tot[3]],
			"directories": dict(dirs),
			"thin": [{"pct": p, "lines": [e, n], "file": f,
				  "line": s, "name": nm, "count": c}
				 for p, e, n, f, s, nm, c in thin],
		}, fp, indent=1)


def main():
	ap = argparse.ArgumentParser()
	ap.add_argument("--include", action="append", default=None,
			help="source prefix to count (default: lib)")
	ap.add_argument("--threshold", type=float, default=50.0,
			help="list functions below this line coverage %% (default 50)")
	ap.add_argument("--limit", type=int, default=0,
			help="max functions to list, 0 = all")
	ap.add_argument("--json", action="store_true",
			help="also write the summary to %s" % JSON_OUT)
	a = ap.parse_args()

	bdir = os.getcwd()
	cache = cmake_cache(("CMAKE_C_COMPILER", "CMAKE_HOME_DIRECTORY"))
	compiler = cache.get("CMAKE_C_COMPILER", "cc")
	sdir = os.path.abspath(cache.get("CMAKE_HOME_DIRECTORY", ".."))
	incl = [p.rstrip("/") + "/" for p in (a.include or ["lib"])]

	tool = find_tool(compiler)
	if not tool:
		print("coverage: no gcov reader found for compiler %s (a clang "
		      "build needs llvm-cov, gcc's gcov cannot read its files); "
		      "nothing to report" % compiler)
		return
	mode = tool_mode(tool)

	gcnos = find_gcnos(bdir)
	if not gcnos:
		print("coverage: no .gcno files under %s; was the tree built with "
		      "-DLWS_WITH_GCOV=1 ?" % bdir)
		return

	gcdas = sum(1 for g in gcnos if os.path.exists(g[:-5] + ".gcda"))
	print("coverage: %d objects instrumented, %d with run data, reader %s (%s)" %
	      (len(gcnos), gcdas, " ".join(tool), mode))

	cov = collect(tool, mode, gcnos, make_norm(bdir, sdir, incl))
	if not cov.files:
		print("coverage: no source under %s matched %s" % (sdir, incl))
		for e in cov.errors[:20]:
			print("  ", e)
		return

	tot, dirs, funcs = summarize(cov)
	thin = print_report(incl, tot, dirs, funcs, a.threshold, a.limit,
			    cov.errors)
	if a.json:
		write_json(tot, dirs, thin)


if __name__ == "__main__":
	main()
	sys.exit(0)
